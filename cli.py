from __future__ import annotations

import pathlib
import time
import sys
import re
import paramiko
import requests
from urllib.parse import urlparse
from .gitlab_version import detect_version
from .utils import docker_volumes_dir

from .vars import (
    BASE_URL, UBUNTU_HOST, UBUNTU_USER,
    UBUNTU_PASSWORD, COMPOSE_DIR,
)
from .vars import (
    GITLAB_IMAGE, GITLAB_CONTAINER_NAME, GITLAB_HOSTNAME,
    GITLAB_HTTP_PORT, GITLAB_HTTPS_PORT, GITLAB_HTTPS_ALT_PORT, GITLAB_RESTART_POLICY,
)
from .ssh_client import SSH
from .docker_compose import ComposeScaffolder
from .docker_pull import Puller
from .gitlab_probe import GitLabProbe
from .upgrader import Upgrader
from .upgrade_path import write_upgrade_path
from .ssl_handler import SSLHandler

# Parsing constants for ls/args/status splits
_LS_MIN_FIELDS = 9
_MIN_CLI_ARGS = 2
_STATUS_MIN_FIELDS = 3


def _require(value: str, name: str) -> None:
    if not value:
        sys.exit(f"❌  Missing env-var {name}")


def _detect_version_from_volumes(remote: SSH) -> tuple[str | None, bool]: # noqa: PLR0911, PLR0912, PLR0915
    """Try to detect GitLab version from existing volume data
    Returns: (version, has_gitlab_data)
    """
    print("🔍 Checking for existing GitLab data in volumes...")

    try:
        volumes_dir = docker_volumes_dir(remote)
        dir_check = remote.run(f"sudo test -d {volumes_dir} && echo 'exists' || echo 'missing'", check=False)

        if "missing" in dir_check:
            print(f"   ❌ Docker volumes directory not found: {volumes_dir}")
            return None, False

        volumes_result = remote.run(f"sudo ls -la {volumes_dir}/ 2>/dev/null", check=False)
        if not volumes_result:
            print("   ❌ Cannot access Docker volumes directory")
            return None, False

        print("   📂 Docker volumes directory contents:")
        gitlab_volumes = []
        for line in volumes_result.split('\n'):
            if 'gitlab' in line.lower() and 'drwx' in line:
                parts = line.split()
                if len(parts) >= _LS_MIN_FIELDS:
                    volume_name = parts[-1]
                    gitlab_volumes.append(volume_name)
                    print(f"     📦 {volume_name}")

        if not gitlab_volumes:
            print("   ❌ No GitLab volumes found")
            return None, False

        has_data = True
        print(f"   ✅ Found {len(gitlab_volumes)} GitLab volume(s)")

        data_volume_paths = [
            f"{volumes_dir}/gitlab_data/_data",
            f"{volumes_dir}/gitlab-data/_data",
        ]

        for data_path in data_volume_paths:
            path_check = remote.run(f"sudo test -d {data_path} && echo 'exists' || echo 'missing'", check=False)
            if "exists" in path_check:
                print(f"   📁 Found GitLab data path: {data_path}")

                version_files = [
                    f"{data_path}/gitlab-rails/VERSION",
                    f"{data_path}/opt/gitlab/embedded/service/gitlab-rails/VERSION",
                    f"{data_path}/var/opt/gitlab/gitlab-rails/VERSION",
                ]

                for version_file in version_files:
                    try:
                        result = remote.run(f"sudo cat '{version_file}' 2>/dev/null", check=False)
                        if result and result.strip():
                            m = re.search(r'(\d+\.\d+\.\d+)', result.strip())
                            if m:
                                version = m.group(1)
                                print(f"   📄 Found GitLab version {version} in {version_file}")
                                return version, True
                    except (RuntimeError, OSError, TimeoutError, paramiko.SSHException):
                        continue

                structure_check = remote.run(f"sudo ls {data_path}/ 2>/dev/null | head -5", check=False)
                if structure_check:
                    print("   📁 GitLab data structure found:")
                    for line in structure_check.split('\n')[:3]:
                        if line.strip():
                            print(f"     • {line.strip()}")

                db_check = remote.run(
                    f"sudo find {data_path} -name 'postgresql' -type d 2>/dev/null | head -1",
                    check=False,
                )
                if db_check and db_check.strip():
                    print("   💾 Found PostgreSQL database in data")

                git_check = remote.run(f"sudo find {data_path} -name '*.git' -type d 2>/dev/null | wc -l", check=False)
                if git_check and git_check.strip() and int(git_check.strip()) > 0:
                    print(f"   📚 Found {git_check.strip()} Git repositories in data")

                return "unknown_with_data", True

        for volume in gitlab_volumes:
            volume_path = f"{volumes_dir}/{volume}/_data"
            content_check = remote.run(f"sudo ls {volume_path}/ 2>/dev/null | head -3", check=False)
            if content_check:
                print(f"   📁 Volume {volume} contains:")
                for line in content_check.split('\n')[:2]:
                    if line.strip():
                        print(f"     • {line.strip()}")

        return "unknown_with_data" if has_data else None, has_data

    except Exception as e:
        print(f"   ⚠️  Error checking volumes: {e}")
        return None, False


def _check_docker_installed(remote: SSH) -> bool:
    try:
        remote.run("docker --version")
        return True
    except (RuntimeError, OSError, TimeoutError, paramiko.SSHException):
        return False


def _detect_current_version(remote: SSH) -> str:
    """Try to detect the current GitLab version for dry_run display"""
    try:
        version, _ = detect_version()
        return version
    except (ImportError, RuntimeError, OSError, requests.RequestException):
        try:
            result = remote.run("docker ps --format '{{.Names}}\t{{.Image}}' | grep gitlab", check=False)
            if result:
                lines = result.strip().split('\n')
                for line in lines:
                    if '\t' in line:
                        name, image = line.split('\t', 1)
                        if 'gitlab' in image.lower():
                            m = re.search(r'(\d+\.\d+\.\d+)', image)
                            if m:
                                return m.group(1)
        except (RuntimeError, OSError, TimeoutError, paramiko.SSHException):
            pass

        try:
            detected_version, _ = _detect_version_from_volumes(remote)
            if detected_version and detected_version != "unknown_with_data":
                return detected_version
        except (RuntimeError, OSError, TimeoutError, paramiko.SSHException):
            pass

    return "Unknown"


def main() -> None: # noqa: PLR0911, PLR0912, PLR0915
    # ── parse subcommand: install | upgrade | dry_run ───
    if len(sys.argv) < _MIN_CLI_ARGS:
        print("Usage: python -m gitlab_docker_upgrader <install|upgrade|dry_run>")
        return

    cmd = sys.argv[1]
    if cmd not in {"install", "upgrade", "dry_run"}:
        print("Unknown command:\nUsage: python -m gitlab_docker_upgrader <install|upgrade|dry_run>")
        return

    dry_run = cmd == "dry_run"
    do_install = cmd == "install"
    do_upgrade = cmd == "upgrade"

    if dry_run:
        print("🧪 DRY RUN MODE - No actual changes will be made")
        print("=" * 50)

    # ── basic sanity checks ───────────────────────────
    _require(UBUNTU_HOST,     "GITLAB_NODE_IP")
    _require(UBUNTU_USER,     "GITLAB_NODE_USER")
    _require(UBUNTU_PASSWORD, "GITLAB_NODE_PASSWORD")
    _require(BASE_URL,        "GITLAB_BASE_URL")
    _require(COMPOSE_DIR,     "GITLAB_COMPOSE_DIR")

    # ── establish SSH connection ──────────────────────
    remote = SSH(UBUNTU_HOST, UBUNTU_USER, UBUNTU_PASSWORD)

    # ── check Docker installation ─────────────────────
    docker_installed = _check_docker_installed(remote)
    if not docker_installed:
        print("❌ Docker Engine not found")
        detected_version, has_gitlab_data = _detect_version_from_volumes(remote)

        if has_gitlab_data:
            print("\n🔄 RECOVERY SCENARIO DETECTED:")
            print("   • Docker Engine is missing")
            print("   • GitLab data exists in volumes")
            if detected_version and detected_version != "unknown_with_data":
                print(f"   • Detected GitLab version: {detected_version}")
            else:
                print("   • GitLab version: Unknown (will start conservatively)")

            if dry_run:
                print("\n📋 RECOVERY PLAN:")
                print("   1. Install Docker Engine and Compose plugin")
                print("   2. Create docker-compose.yml")
                if detected_version and detected_version != "unknown_with_data":
                    print(f"   3. Start GitLab {detected_version} with existing data")
                    print("   4. Wait for GitLab API to become available")
                    print("   5. Detect actual version via API")
                    print("   6. Build and execute upgrade path")
                else:
                    print("   3. Start GitLab 15.0.0 (conservative) with existing data")
                    print("   4. Wait for GitLab API to become available")
                    print("   5. Detect actual version via API")
                    print("   6. Build and execute upgrade path")

                print("\n⚠️  IMPORTANT: After Docker installation, restart the script to continue.")
                remote.close()
                return
            else:
                print("\n📦 Installing Docker Engine first is required; please install and rerun.")
                remote.close()
                return
        else:
            print("   No existing GitLab data found")
            if dry_run:
                print("\n📋 FRESH INSTALLATION PLAN:")
                print("   1. Install Docker Engine and Compose plugin")
                print("   2. Create docker-compose.yml")
                print("   3. Install latest GitLab version")
                print("\n🎯 To perform fresh installation:")
                print("   python -m gitlab_docker_upgrader")
                remote.close()
                return
            # If not dry-run, you would install Docker here in a real flow

    # ── SSL pre-check (non-destructive) ─────────────────
    ssl_handler = None
    domain = urlparse(BASE_URL).hostname
    ssl_already_configured = False
    if domain:
        ssl_handler = SSLHandler(remote)
        try:
            if ssl_handler.is_ssl_configured(domain):
                ssl_already_configured = True
                print(f"✅ SSL certificate already configured for {domain}")
            else:
                print(f"ℹ️  SSL not configured for {domain}; will configure during install/upgrade if needed")
        except Exception as e:
            print(f"⚠️  SSL configuration check failed: {e}")

    # ── discover container state ────────────────────────
    print("🔍 Pre-flight check: Looking for GitLab containers...")
    try:
        result = remote.run("docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' | grep gitlab", check=False)
        gitlab_found = False
        gitlab_running = False
        container_name = None

        if result:
            lines = result.strip().split('\n')
            for line in lines:
                if '\t' in line:
                    parts = line.split('\t')
                    if len(parts) >= _STATUS_MIN_FIELDS:
                        name, image, status = parts[0], parts[1], parts[2]
                        if 'gitlab' in image.lower():
                            gitlab_found = True
                            container_name = name
                            if 'Up' in status:
                                gitlab_running = True
                                print(f"✅ Found running GitLab container: {name}")
                                break
                            else:
                                print(f"🔴 Found stopped GitLab container: {name}")

        if gitlab_found and not gitlab_running:
            print("❌ ERROR: GitLab container exists but is not running!")
            print("   Cannot determine current version for upgrade path.")
            print(f"   Please start GitLab first: docker start {container_name}")
            print("   Then run the upgrade again.")
            sys.exit(1)

        elif not gitlab_found:
            print("📝 No GitLab containers found")

            detected_version, has_gitlab_data = _detect_version_from_volumes(remote)
            if has_gitlab_data:
                print("🔄 Found GitLab data but no containers (recovery scenario)")
                if dry_run:
                    print("\n📋 RECOVERY PLAN:")
                    if detected_version and detected_version != "unknown_with_data":
                        print("   1. Create docker-compose.yml")
                        print(f"   2. Start GitLab {detected_version} with existing data")
                        print("   3. Wait for API to become available")
                        print("   4. Build and execute upgrade path")
                        print(f"\n💡 Detected version: {detected_version}")
                    else:
                        print("   1. Create docker-compose.yml")
                        print("   2. Start GitLab 15.0.0 (conservative) with existing data")
                        print("   3. Wait for API to become available")
                        print("   4. Detect actual version via API")
                        print("   5. Build and execute upgrade path")
                        print("\n⚠️  Version unknown - will start conservatively")

                    print("\n🎯 To perform the recovery:")
                    print("   python -m gitlab_docker_upgrader")
                    remote.close()
                    return
            else:
                print("📝 No GitLab data found - fresh installation")
                if do_install:
                    # Если SSL нужен, готовим файлы заранее, чтобы compose сделал bind-mount
                    if ssl_handler and not ssl_already_configured:
                        try:
                            domain = urlparse(BASE_URL).hostname
                            if domain:
                                print("🔐 Preparing SSL certs before composing …")
                                ssl_handler.ensure_ready(domain)
                                ssl_already_configured = True
                        except Exception as e:
                            print(f"⚠️  SSL preparation failed (will fall back to named volume): {e}")

                    compose = ComposeScaffolder(remote, COMPOSE_DIR, ssl_handler=ssl_handler)
                    compose.scaffold_from_template(
                        image=GITLAB_IMAGE,
                        hostname=GITLAB_HOSTNAME,
                        http_port=GITLAB_HTTP_PORT,
                        https_port=GITLAB_HTTPS_PORT,
                        https_alt_port=GITLAB_HTTPS_ALT_PORT,
                        restart_policy=GITLAB_RESTART_POLICY,
                    )
                    cmp_cmd = compose._compose_cmd()
                    print(f"▶️  Running '{cmp_cmd} up -d' on remote host...")
                    remote.run(f"cd '{COMPOSE_DIR}' && {cmp_cmd} up -d")
                    print("✅ GitLab is starting…")

                    # ── NEW: print initial root password on fresh install ───────────────────

                    container = GITLAB_CONTAINER_NAME or "gitlab"
                    path = "/etc/gitlab/initial_root_password"
                    print("🔐 Waiting for initial root password to be generated …")

                    password = ""
                    deadline = time.time() + 900  # up to 15 minutes
                    while time.time() < deadline:
                        # try to grab just the password line; returns empty until file exists
                        out = remote.run(
                            f"docker exec {container} bash -lc \"[ -f '{path}' ] && "
                            f"sed -n 's/^Password: \\(.*\\)$/\\1/p' '{path}' || true\"",
                            check=False,
                        ).strip()

                        if out:
                            password = out.splitlines()[0].strip()
                            break

                        time.sleep(10)

                    if password:
                        print("\n================= INITIAL ROOT PASSWORD =================")
                        print(f"root password: {password}")
                        print("=========================================================\n")
                        print("ℹ️  Save it securely. The file will be removed automatically by GitLab in ~24h.")
                    else:
                        print("⚠️  Could not read initial root password yet. You can get it later with:")
                        print(
                            f"    docker exec -it {container} bash -lc "
                            f"\"sed -n 's/^Password: \\(.*\\)$/\\1/p' {path}\""
                        )

                    remote.close()
                    return

                if dry_run:
                    print("\n📋 FRESH INSTALLATION PLAN:")
                    print("   1. Create docker-compose.yml using template and .env")
                    print("   2. Start GitLab with configured image and volumes")
                    print("\n🎯 To perform the fresh installation run without dry_run:")
                    print("   python -m gitlab_docker_upgrader install")
                    remote.close()
                    return

                if do_upgrade:
                    print(
                        "❌ No GitLab containers or data found to upgrade. "
                        "Use 'install' to perform fresh installation."
                    )
                    remote.close()
                    return

    except Exception as e:
        print(f"⚠️  Could not check GitLab status: {e}")
        gitlab_running = False

    # ── If GitLab is running, optionally ensure SSL (non-destructive here) ──
    if 'gitlab_running' in locals() and gitlab_running:
        domain = urlparse(BASE_URL).hostname
        ssl_handler = SSLHandler(remote)
        try:
            if ssl_handler.is_ssl_configured(domain):
                print(f"✅ SSL certificate already configured for {domain}")
            else:
                print(f"⚠️  SSL not configured for {domain} (will prepare during upgrade)")
        except Exception as e:
            print(f"⚠️  SSL check failed: {e}")

    # ── build / refresh upgrade_path.txt ──────────────
    if 'gitlab_running' in locals() and gitlab_running:
        try:
            if write_upgrade_path() == 0:
                print("GitLab already up-to-date.")
                remote.close()
                return
            ladder = pathlib.Path("upgrade_path.txt").read_text().splitlines()
        except Exception as e:
            print(f"❌ Could not determine upgrade path: {e}")
            print("   Make sure GitLab is accessible via HTTP/HTTPS")
            sys.exit(1)
    else:
        ladder = []

    # ── dry_run mode output ──────────────────────────
    if dry_run:
        if ladder:
            print(f"\n📋 UPGRADE PLAN ({len(ladder)} steps):")
            print("─" * 40)
            current_version = _detect_current_version(remote)
            print(f"Current: {current_version}")
            for i, version in enumerate(ladder, 1):
                print(f"Step {i:2d}: {version}")
            print("\n📊 UPGRADE SUMMARY:")
            print(f"   • Total steps: {len(ladder)}")
            print(f"   • Final version: {ladder[-1] if ladder else 'N/A'}")
            est_min = len(ladder) * 12  # грубая оценка
            print(f"   • Estimated time: ~{est_min} minutes")
            print("\n🎯 To perform the actual upgrade, run without dry_run:")
            print("   python -m gitlab_docker_upgrader")
        else:
            detected_version, has_gitlab_data = _detect_version_from_volumes(remote)
            if has_gitlab_data:
                print("\n🔄 RECOVERY SCENARIO DETECTED:")
                if detected_version and detected_version != "unknown_with_data":
                    print(f"   • Detected GitLab version: {detected_version}")
                    print("   • Plan: create docker-compose.yml and start GitLab with existing data")
                else:
                    print("   • GitLab data present but version unknown")
                    print("   • Plan: start conservative GitLab image with existing data and detect version")
                print("\n🎯 To perform the recovery, run without dry_run:")
                print("   python -m gitlab_docker_upgrader")
            else:
                print("\n📋 FRESH INSTALLATION PLAN:")
                print("   1. Create docker-compose.yml using template and .env")
                print("   2. Start GitLab with configured image and volumes")
                print("\n🎯 To perform the fresh installation run without dry_run:")
                print("   python -m gitlab_docker_upgrader install")

        remote.close()
        return

    # ── do the upgrade (or recovery path) ─────────────
    compose = ComposeScaffolder(remote, COMPOSE_DIR, ssl_handler=ssl_handler)
    puller = Puller()
    probe = GitLabProbe(BASE_URL, remote)

    if ladder:
        Upgrader(remote, compose, puller, probe).run(ladder)
    else:
        print("🏁 No upgrade needed or fresh installation completed")
        remote.close()
