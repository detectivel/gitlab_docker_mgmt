from __future__ import annotations

import io
import os
import pathlib
import re
import sys
import time
import shlex
from urllib.parse import urlparse
from typing import Tuple, Optional

import paramiko
import requests

from .gitlab_version import detect_version
from .utils import docker_volumes_dir, get_logger, route_prints_to_logger
from .vars import GITLAB_NODE_KEY_FILE, GITLAB_NODE_KEY_PASSPHRASE
from .vars import (
    BASE_URL, UBUNTU_HOST, UBUNTU_USER,
    UBUNTU_PASSWORD, COMPOSE_DIR,
)
from .vars import (
    GITLAB_CONTAINER_NAME, GITLAB_HOSTNAME, GITLAB_IMAGE,
    GITLAB_HTTP_PORT, GITLAB_HTTPS_PORT, GITLAB_HTTPS_ALT_PORT, GITLAB_RESTART_POLICY,
)
from .ssh_client import SSH
from .docker_compose import ComposeScaffolder
from .docker_pull import Puller
from .gitlab_probe import GitLabProbe
from .upgrader import Upgrader
from .upgrade_path import write_upgrade_path
from .ssl_handler import SSLHandler
from .docker_gc import cleanup_old_images   # <-- NEW

# Parsing constants
_LS_MIN_FIELDS = 9
_MIN_CLI_ARGS = 2
_STATUS_MIN_FIELDS = 3

_PG_INCOMPAT_RE = re.compile(
    r"initialized by PostgreSQL version (\d+).+not compatible with this version (\d+)",
    re.IGNORECASE | re.DOTALL,
)

def _pg_incompat_detect(remote: SSH, container: str = "gitlab") -> tuple[bool, int | None, int | None, str]:
    cmd = (
        f"docker exec {shlex.quote(container)} bash -lc "
        f"\"test -f /var/log/gitlab/postgresql/current && "
        f"tail -n 400 /var/log/gitlab/postgresql/current || "
        f"echo 'NOLOG'\""
    )
    try:
        out = remote.run(cmd, check=False) or ""
    except Exception:
        out = ""
    m = _PG_INCOMPAT_RE.search(out)
    if not m:
        return False, None, None, ""
    try:
        dv = int(m.group(1))
        sv = int(m.group(2))
    except Exception:
        dv = sv = None
    bad_line = ""
    for line in out.splitlines():
        if "database files are incompatible" in line or "initialized by PostgreSQL version" in line:
            bad_line = line.strip()
            break
    return True, dv, sv, bad_line

def _pg_upgrade_auto(remote: SSH, container: str = "gitlab", max_retries: int = 3) -> None:
    print("🛠  Detected PG major mismatch. Running 'gitlab-ctl pg-upgrade' …")
    for attempt in range(1, max_retries + 1):
        out, rc = remote.run_with_status(
            f"docker exec {shlex.quote(container)} bash -lc 'gitlab-ctl pg-upgrade'"
        )
        if rc == 0:
            print(f"✅ pg-upgrade finished on attempt {attempt}")
            break
        else:
            print(f"⚠️  pg-upgrade attempt {attempt} failed (rc={rc}). Retrying in 10s …")
            time.sleep(10)
    else:
        sys.exit("❌  pg-upgrade failed after multiple attempts")

    remote.run(f"docker exec {shlex.quote(container)} gitlab-ctl reconfigure", check=False)
    remote.run(f"docker exec {shlex.quote(container)} gitlab-ctl restart", check=False)


def _try_fix_pg_incompat(remote: SSH, container: str = "gitlab") -> bool:
    found, dv, sv, line = _pg_incompat_detect(remote, container)
    if not found:
        return True

    print(f"🔴 PostgreSQL data/server major mismatch: data={dv}, server={sv}")
    if line:
        print(f"    {line}")
    _pg_upgrade_auto(remote, container)

    again, *_ = _pg_incompat_detect(remote, container)
    if again:
        print("❌  PG incompatibility persists after pg-upgrade")
        return False
    print("✅ PostgreSQL incompatibility resolved.")
    return True

def _require(value: str, name: str) -> None:
    """Exit with a helpful message if a required env-var is missing."""
    if not value:
        sys.exit(f"Missing env-var {name}")

def _load_private_key_any(path_or_pem: str, passphrase: str) -> paramiko.PKey:
    """
    Load an encrypted private key either from a filesystem PATH or PEM content.
    Tries Ed25519 → ECDSA → RSA.
    """
    def _try_with(cls, src):
        if isinstance(src, str) and os.path.exists(src):
            return cls.from_private_key_file(src, password=passphrase or None)
        # src is PEM content
        return cls.from_private_key(io.StringIO(src), password=passphrase or None)

    last_err = None
    for key_cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return _try_with(key_cls, path_or_pem)
        except FileNotFoundError as e:
            last_err = e
            break
        except paramiko.PasswordRequiredException as e:
            last_err = e
        except paramiko.SSHException as e:
            last_err = e
    msg = str(last_err) if last_err else "unknown error"
    sys.exit(f"Unable to load SSH key: {msg}")

def _parse_days(not_after_str: str) -> Optional[int]:
    """Parse OpenSSL notAfter output into integer 'days left'."""
    m = re.search(r"notAfter=(.+)", not_after_str or "")
    if not m:
        return None
    s = " ".join(m.group(1).split())
    from datetime import datetime, timezone
    try:
        dt = datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        try:
            dt = datetime.strptime(s, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        except Exception:
            return None
    now = datetime.now(timezone.utc)
    return int((dt - now).days)

def _print_cert_status(remote: SSH, hostname: str, ssl_host_dir: str) -> None:
    """Log certificate presence and expiry (days left)."""
    log = get_logger()
    crt_host = f"{ssl_host_dir.rstrip('/')}/{hostname}.crt"

    # host bind path
    _ , rc = remote.run_with_status(f"test -f '{crt_host}'")
    if rc == 0:
        out, _ = remote.run_with_status(f"openssl x509 -in '{crt_host}' -noout -dates")
        days = _parse_days(out or "")
        status = f"{days} days left" if isinstance(days, int) else "unknown expiry"
        log.info(f"TLS: host bind cert present at {crt_host} -> {status}")
        return

    # try inside container
    name_out, rc = remote.run_with_status("docker ps --format '{{.Names}}\t{{.Image}}' | grep gitlab")
    if rc == 0 and name_out.strip():
        container = name_out.split("\t", 1)[0].strip()
        crt_in = f"/etc/gitlab/ssl/{hostname}.crt"
        _ , rc2 = remote.run_with_status(f"docker exec {container} test -f '{crt_in}'")
        if rc2 == 0:
            out, _ = remote.run_with_status(f"docker exec {container} openssl x509 -in '{crt_in}' -noout -dates")
            days = _parse_days(out or "")
            status = f"{days} days left" if isinstance(days, int) else "unknown expiry"
            log.info(f"TLS: in-container cert present at {crt_in} -> {status}")
            return

    log.warning("TLS: certificate not found (host bind nor in-container)")

def _compose_reconfigure_nginx(remote: SSH, container_name: str = "gitlab") -> None:
    """Best-effort nginx reload after cert renewal."""
    log = get_logger()
    try:
        remote.run(f"docker exec -t {container_name} gitlab-ctl reconfigure", check=False)
        remote.run(f"docker exec -t {container_name} gitlab-ctl restart nginx", check=False)
    except Exception as e:
        log.warning(f"Reconfigure failed (non-fatal): {e}")

def _check_docker_installed(remote: SSH) -> bool:
    try:
        remote.run("docker --version")
        return True
    except (RuntimeError, OSError, TimeoutError, paramiko.SSHException):
        return False

def _detect_version_from_volumes(remote: SSH) -> Tuple[Optional[str], bool]:
    """Detect GitLab version from existing data volumes.
    Returns: (version, has_gitlab_data)
    """
    log = get_logger()
    log.info("Checking for existing GitLab data in volumes...")
    try:
        volumes_dir = docker_volumes_dir(remote)
        dir_check = remote.run(f"sudo test -d {volumes_dir} && echo 'exists' || echo 'missing'", check=False)

        if "missing" in dir_check:
            log.error(f"Docker volumes directory not found: {volumes_dir}")
            return None, False

        volumes_result = remote.run(f"sudo ls -la {volumes_dir}/ 2>/dev/null", check=False)
        if not volumes_result:
            log.error("Cannot access Docker volumes directory")
            return None, False

        log.debug("Docker volumes directory listing obtained")
        gitlab_volumes = []
        for line in volumes_result.split('\n'):
            if 'gitlab' in line.lower() and 'drwx' in line:
                parts = line.split()
                if len(parts) >= _LS_MIN_FIELDS:
                    volume_name = parts[-1]
                    gitlab_volumes.append(volume_name)
                    log.debug(f"Volume: {volume_name}")

        if not gitlab_volumes:
            log.error("No GitLab volumes found")
            return None, False

        has_data = True
        log.info(f"Found {len(gitlab_volumes)} GitLab volume(s)")

        data_volume_paths = [
            f"{volumes_dir}/gitlab_data/_data",
            f"{volumes_dir}/gitlab-data/_data",
        ]

        for data_path in data_volume_paths:
            path_check = remote.run(f"sudo test -d {data_path} && echo 'exists' || echo 'missing'", check=False)
            if "exists" in path_check:
                log.info(f"Found GitLab data path: {data_path}")

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
                                log.info(f"Found GitLab version {version} in {version_file}")
                                return version, True
                    except (RuntimeError, OSError, TimeoutError, paramiko.SSHException):
                        continue

                structure_check = remote.run(f"sudo ls {data_path}/ 2>/dev/null | head -5", check=False)
                if structure_check:
                    for line in structure_check.split('\n')[:3]:
                        if line.strip():
                            log.debug(f"Data entry: {line.strip()}")

                db_check = remote.run(
                    f"sudo find {data_path} -name 'postgresql' -type d 2>/dev/null | head -1",
                    check=False,
                )
                if db_check and db_check.strip():
                    log.info("Found PostgreSQL database in data")

                git_check = remote.run(f"sudo find {data_path} -name '*.git' -type d 2>/dev/null | wc -l", check=False)
                if git_check and git_check.strip() and int(git_check.strip()) > 0:
                    log.info(f"Found {git_check.strip()} Git repositories in data")

                return "unknown_with_data", True

        for volume in gitlab_volumes:
            volume_path = f"{volumes_dir}/{volume}/_data"
            content_check = remote.run(f"sudo ls {volume_path}/ 2>/dev/null | head -3", check=False)
            if content_check:
                for line in content_check.split('\n')[:2]:
                    if line.strip():
                        log.debug(f"{volume}: {line.strip()}")

        return "unknown_with_data" if has_data else None, has_data

    except Exception as e:
        log.warning(f"Error checking volumes: {e}")
        return None, False

def _detect_current_version(remote: SSH) -> str:
    """Try to detect the current GitLab version for dry_run display."""
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

def _detect_gitlab_container_name(remote: SSH) -> str:
    """
    Return the first running/stopped container name that looks like gitlab.
    Fallback to GITLAB_CONTAINER_NAME or 'gitlab'.
    """
    # first try running
    out, rc = remote.run_with_status("docker ps --format '{{.Names}}\t{{.Image}}' | grep -i gitlab || true")
    if rc == 0 and out.strip():
        return out.split("\t", 1)[0].strip()
    # then try all
    out2, rc2 = remote.run_with_status("docker ps -a --format '{{.Names}}\t{{.Image}}' | grep -i gitlab || true")
    if rc2 == 0 and out2.strip():
        return out2.split("\t", 1)[0].strip()
    return GITLAB_CONTAINER_NAME or "gitlab"

def _infer_repo_ref_from_image(default_ce: str = "gitlab/gitlab-ce:*", default_ee: str = "gitlab/gitlab-ee:*") -> str:
    """
    Infer repo reference (ce/ee) from configured GITLAB_IMAGE; fallback to CE.
    """
    img = (GITLAB_IMAGE or "").lower()
    if "gitlab-ee" in img:
        return default_ee
    return default_ce

def main() -> None:  # noqa: PLR0911, PLR0912, PLR0915
    # ── parse subcommand: install | upgrade | dry_run ───
    if len(sys.argv) < _MIN_CLI_ARGS:
        print("Usage: python -m <project> <install|upgrade|dry_run|status|revise_version|cert_renew|start|images_cleanup>")
        return

    cmd = sys.argv[1]
    if cmd not in {"install", "upgrade", "dry_run", "status", "revise_version", "cert_renew", "start", "images_cleanup"}:
        print("Unknown command:\n"
              "Usage: python -m <project> <install|upgrade|dry_run|status|revise_version|cert_renew|start|images_cleanup>")
        return

    dry_run = cmd == "dry_run"
    do_install = cmd == "install"
    do_upgrade = cmd == "upgrade"
    status = cmd == "status"
    revise_version = cmd == "revise_version"
    cert_renew = cmd == "cert_renew"
    start = cmd == "start"
    images_cleanup = cmd == "images_cleanup"

    # Initialize logging (console/file/JSON) based on env/vars
    logger = get_logger()
    # Optionally route legacy prints through logger (LOG_REDIRECT_PRINT=1)
    if os.getenv("LOG_REDIRECT_PRINT", "1").lower() in {"1", "true", "yes", "y"}:
        route_prints_to_logger()

    if dry_run:
        print("DRY RUN MODE - No actual changes will be made")
        print("=" * 50)

    # ── basic sanity checks ───────────────────────────
    _require(UBUNTU_HOST, "GITLAB_NODE_IP")
    _require(UBUNTU_USER, "GITLAB_NODE_USER")
    _require(BASE_URL,    "GITLAB_BASE_URL")
    _require(COMPOSE_DIR, "GITLAB_COMPOSE_DIR")

    # ── establish SSH connection ──────────────────────
    if not (UBUNTU_PASSWORD or GITLAB_NODE_KEY_FILE):
        sys.exit("No SSH credentials: set either UBUNTU_PASSWORD or GITLAB_NODE_KEY_FILE")

    ssh_kwargs: dict = {}
    if GITLAB_NODE_KEY_FILE:
        try:
            if os.path.exists(GITLAB_NODE_KEY_FILE) or GITLAB_NODE_KEY_FILE.strip().startswith("-----BEGIN"):
                pkey_obj = _load_private_key_any(GITLAB_NODE_KEY_FILE, GITLAB_NODE_KEY_PASSPHRASE or "")
                ssh_kwargs["pkey"] = pkey_obj
            else:
                ssh_kwargs["key_filename"] = GITLAB_NODE_KEY_FILE
        except SystemExit:
            raise
        except Exception as e:
            sys.exit(f"Failed to prepare SSH key: {e}")

    # Disable agent and auto key lookup to avoid Paramiko agent issues
    ssh_kwargs["allow_agent"] = False
    ssh_kwargs["look_for_keys"] = False

    remote = SSH(
        UBUNTU_HOST,
        UBUNTU_USER,
        pw=UBUNTU_PASSWORD or None,
        **ssh_kwargs
    )

    # ── images_cleanup subcommand ─────────────────────
    if images_cleanup:
        try:
            container = _detect_gitlab_container_name(remote)
            repo_ref = _infer_repo_ref_from_image()
            cleanup_old_images(remote, container_name=container, repo_ref=repo_ref)
            print(f"Images cleanup done for repo_ref='{repo_ref}', preserved container image '{container}'.")
        finally:
            remote.close()
        return

    # ── subcommands ───────────────────────────────────
    if status:
        probe = GitLabProbe(BASE_URL, remote)
        try:
            ver = probe.version() or "unknown"
        except Exception:
            ver = "unknown"
        try:
            docker_health = probe._docker_health()
        except Exception:
            docker_health = "unknown"
        print(f"GitLab status: docker={docker_health}, version={ver}")
        _print_cert_status(remote, GITLAB_HOSTNAME, ssl_host_dir=f"{COMPOSE_DIR.rstrip('/')}/gitlab/config/ssl")
        remote.close()
        return

    if revise_version:
        compose = ComposeScaffolder(remote, COMPOSE_DIR)
        compose.ensure()
        probe = GitLabProbe(BASE_URL, remote)
        current = None
        try:
            current = probe.version()
        except Exception:
            pass
        if not current:
            print("Cannot determine current GitLab version (container must be running).")
            remote.close()
            return
        try:
            compose.pin_latest_to(current)
            print(f"Revised docker-compose.yml: pinned ':latest' -> '{current}-<edition>.0'")
        except Exception as e:
            print(f"Failed to revise compose tag: {e}")
        remote.close()
        return

    if cert_renew:
        ssl_handler = SSLHandler(remote)
        try:
            crt, key = ssl_handler.generate_self_signed_cert(GITLAB_HOSTNAME, days=825)
            print(f"New self-signed TLS issued:\n   CRT: {crt}\n   KEY: {key}")
            out, rc = remote.run_with_status("docker ps --format '{{.Names}}\t{{.Image}}' | grep gitlab")
            if rc == 0 and out.strip():
                container = out.split("\t", 1)[0].strip()
                _compose_reconfigure_nginx(remote, container)
        except Exception as e:
            print(f"Certificate renewal failed: {e}")
        remote.close()
        return

    if start:
        out, rc = remote.run_with_status("docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' | grep gitlab")
        if rc == 0 and out.strip() and "Up " in out:
            name = out.split("\t", 1)[0].strip()
            print(f"GitLab is already running: {name}")
            remote.close()
            return

        out_all, rc_all = remote.run_with_status("docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' | grep gitlab")
        if rc_all == 0 and out_all.strip():
            name = out_all.split("\t", 1)[0].strip()
            _, rc_start = remote.run_with_status(f"docker start {name}")
            if rc_start == 0:
                print(f"Starting existing container: {name}")
                try:
                    ok = _try_fix_pg_incompat(remote, container=name)
                except Exception as e:
                    print(f"PG auto-fix failed (non-fatal): {e}")
                    ok = True
                if not ok:
                    remote.close()
                    return
                try:
                    probe = GitLabProbe(BASE_URL, remote)
                    expect = probe.version() or ""
                    probe.wait_healthy(expect)
                    # FIX: use the 'name' variable we already have here
                    probe.wait_migrations_done(name)
                except Exception:
                    pass
                _print_cert_status(remote, GITLAB_HOSTNAME, ssl_host_dir=f"{COMPOSE_DIR.rstrip('/')}/gitlab/config/ssl")
                remote.close()
                return
            else:
                print(f"Could not start existing container '{name}', will try compose up …")

        ssl_handler = SSLHandler(remote)
        try:
            ssl_handler.ensure_ready(GITLAB_HOSTNAME)
        except Exception as e:
            print(f"TLS preparation failed (continuing): {e}")

        compose = ComposeScaffolder(remote, COMPOSE_DIR, ssl_handler=ssl_handler)
        compose.ensure()
        cmp_cmd = compose._compose_cmd()

        edition = "ce"
        try:
            if hasattr(compose, "_detect_edition"):
                edition = compose._detect_edition()
                if edition not in ("ce", "ee"):
                    edition = "ce"
        except Exception:
            pass

        pull_arg = ""
        try:
            pattern = r'^\s*image:\s*gitlab/gitlab-(ce|ee):'
            img_line, rc_grep = remote.run_with_status(
                f"grep -E {shlex.quote(pattern)} {shlex.quote(compose.compose_file)}"
            )
            if rc_grep == 0 and img_line:
                image = img_line.split('image:', 1)[1].strip()
                _, rc_img = remote.run_with_status(f"docker image inspect {image} --format '{{{{.Id}}}}'")
                if rc_img == 0:
                    pull_arg = "--pull=never"
        except Exception:
            pass

        print(f"Running '{cmp_cmd} up -d {pull_arg}'.")
        try:
            remote.run(f"cd '{COMPOSE_DIR}' && {cmp_cmd} up -d {pull_arg}".strip())
        except RuntimeError as e:
            msg = str(e)
            if "503 Service Unavailable" in msg:
                print("Registry 503 on compose up; retrying once with pre-pull …")
                try:
                    if 'image' in locals() and image:
                        remote.run(f"docker pull {image}", check=False)
                    remote.run(f"cd '{COMPOSE_DIR}' && {cmp_cmd} up -d --pull=never")
                except Exception:
                    raise
            else:
                raise

        # Post-start checks:
        try:
            cname = _detect_gitlab_container_name(remote)
            ok = _try_fix_pg_incompat(remote, cname)
            if not ok:
                remote.close()
                return

            probe = GitLabProbe(BASE_URL, remote)
            expect = probe.version() or ""
            probe.wait_healthy(expect)
            probe.wait_migrations_done(cname)
            _compose_reconfigure_nginx(remote, container_name=cname)
        except Exception as e:
            print(f"Post-start checks: {e}")

        _print_cert_status(remote, GITLAB_HOSTNAME, ssl_host_dir=f"{COMPOSE_DIR.rstrip('/')}/gitlab/config/ssl")
        print("GitLab started")
        remote.close()
        return

    # ── check Docker installation ─────────────────────
    docker_installed = _check_docker_installed(remote)
    if not docker_installed:
        detected_version, has_gitlab_data = _detect_version_from_volumes(remote)
        if dry_run:
            print("\nRECOVERY PLAN:")
            print("   1. Install Docker Engine and Compose plugin")
            print("   2. Create docker-compose.yml")
            if has_gitlab_data and detected_version and detected_version != "unknown_with_data":
                print(f"   3. Start GitLab {detected_version} with existing data")
                print("   4. Wait for GitLab API to become available")
                print("   5. Detect actual version via API")
                print("   6. Build and execute upgrade path")
            else:
                print("   3. Start GitLab 15.0.0 (conservative) with existing data")
                print("   4. Wait for GitLab API to become available")
                print("   5. Detect actual version via API")
                print("   6. Build and execute upgrade path")
            print("\nIMPORTANT: After Docker installation, restart the script to continue.")
        else:
            print("\nInstalling Docker Engine first is required; please install and rerun.")
        remote.close()
        return

    # ── Pre-flight: GitLab container state ────────────
    print("Pre-flight check: Looking for GitLab containers...")
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
                                print(f"Found running GitLab container: {name}")
                                break
                            else:
                                print(f"Found stopped GitLab container: {name}")
    except Exception as e:
        print(f"Could not check GitLab status: {e}")
        gitlab_running = False

    # ── If GitLab is running, optionally ensure SSL (non-destructive here) ──
    if 'gitlab_running' in locals() and gitlab_running:
        domain = urlparse(BASE_URL).hostname
        ssl_handler = SSLHandler(remote)
        try:
            if ssl_handler.is_ssl_configured(domain):
                print(f"SSL certificate already configured for {domain}")
            else:
                print(f"SSL not configured for {domain} (will prepare during upgrade)")
        except Exception as e:
            print(f"SSL check failed: {e}")

        # ── build / refresh upgrade_path.txt ──────────────
        try:
            if write_upgrade_path() == 0:
                print("GitLab already up-to-date.")
                remote.close()
                return
            ladder = pathlib.Path("upgrade_path.txt").read_text().splitlines()
        except Exception as e:
            print(f"Could not determine upgrade path: {e}")
            print("Make sure GitLab is accessible via HTTP/HTTPS")
            remote.close()
            sys.exit(1)
    else:
        ladder = []

    # ── dry_run mode output ──────────────────────────
    if dry_run:
        if ladder:
            print(f"\nUPGRADE PLAN ({len(ladder)} steps):")
            print("─" * 40)
            current_version = _detect_current_version(remote)
            print(f"Current: {current_version}")
            for i, version in enumerate(ladder, 1):
                print(f"Step {i:2d}: {version}")
            print("\nUPGRADE SUMMARY:")
            print(f"   • Total steps: {len(ladder)}")
            print(f"   • Final version: {ladder[-1] if ladder else 'N/A'}")
            est_min = len(ladder) * 12
            print(f"   • Estimated time: ~{est_min} minutes")
            print("\nTo perform the actual upgrade, run without dry_run:")
            print("   python -m gitlab_docker_upgrader")
            remote.close()
            return
        else:
            detected_version, has_gitlab_data = _detect_version_from_volumes(remote)
            if has_gitlab_data:
                print("\nRECOVERY SCENARIO DETECTED:")
                if detected_version and detected_version != "unknown_with_data":
                    print(f"   • Detected GitLab version: {detected_version}")
                    print("   • Plan: create docker-compose.yml and start GitLab with existing data")
                else:
                    print("   • GitLab data present but version unknown")
                    print("   • Plan: start conservative GitLab image with existing data and detect version")
                print("\nTo perform the recovery, run without dry_run:")
                print("   python -m gitlab_docker_upgrader")
                remote.close()
                return
            else:
                print("\nFRESH INSTALLATION PLAN:")
                print("   1. Create docker-compose.yml using template and .env")
                print("   2. Start GitLab with configured image and volumes")
                print("\nTo perform the fresh installation run without dry_run:")
                print("   python -m gitlab_docker_upgrader install")
                remote.close()
                return

    # ── do the upgrade (or fresh install start) ───────
    ssl_handler = SSLHandler(remote) if 'ssl_handler' in locals() else None
    compose = ComposeScaffolder(remote, COMPOSE_DIR, ssl_handler=ssl_handler)
    puller = Puller()
    probe = GitLabProbe(BASE_URL, remote)

    if ladder:
        Upgrader(remote, compose, puller, probe).run(ladder)
        try:
            cname = _detect_gitlab_container_name(remote)
            _try_fix_pg_incompat(remote, container=cname)
        except Exception:
            pass
        remote.close()
    else:
        print("No upgrade needed or fresh installation completed")
        remote.close()


if __name__ == "__main__":
    main()
