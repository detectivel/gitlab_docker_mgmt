from __future__ import annotations

import pathlib
import sys
import re
import os
from typing import List, Optional, Tuple

from .ssh_client import SSH
from .docker_compose import ComposeScaffolder
from .docker_pull import Puller
from .gitlab_probe import GitLabProbe
from .vars import GITLAB_HOSTNAME, GITLAB_SSL_BIND, UBUNTU_USER
from .utils import get_logger, log_info, log_warn, log_fail, log_ok
from .utils import docker_volumes_dir


_PG_INCOMPAT_RE = re.compile(
    r"database files are incompatible with server", re.IGNORECASE
)
_PG_VERSION_RE = re.compile(r"(\d+)\.(\d+)")


class Upgrader:
    """Coordinates Compose scaffolding, pulls, Postgres fixups, and health checks."""

    def __init__(
        self,
        remote: SSH,
        compose: ComposeScaffolder,
        puller: Puller,
        probe: GitLabProbe,
    ):
        self.remote = remote
        self.compose = compose
        self.puller = puller
        self.probe = probe
        self.gitlab_container_name: Optional[str] = None
        self._started_marker_written = False

    # ----------------------------- markers ------------------------------

    def _persist_started_version_once(self, ver: str | None) -> None:
        """Create STARTED_UPGRADE_VERSION once and write version string."""
        if self._started_marker_written:
            return
        if not ver:
            return
        home = f"/home/{UBUNTU_USER}"
        flag = f"{home}/STARTED_UPGRADE_VERSION"
        _out, rc = self.remote.run_with_status(f"test -f '{flag}'", trace=False)
        if rc != 0:
            self.remote.run(
                f"bash -lc \"touch '{flag}' && printf '%s' '{ver}' > '{flag}'\"",
                check=False,
                trace=False,
            )
        self._started_marker_written = True

    def _persist_current_version(self, ver: str | None) -> None:
        """Write CURRENT_VERSION on each successful step."""
        if not ver:
            return
        home = f"/home/{UBUNTU_USER}"
        path = f"{home}/CURRENT_VERSION"
        self.remote.run(
            f"bash -lc \"touch '{path}' && printf '%s' '{ver}' > '{path}'\"",
            check=False,
            trace=False,
        )

    # ------------------------- volume probing ---------------------------

    def _detect_version_from_volumes(self) -> Optional[str]:
        """Try to detect GitLab version from existing volume data."""
        log_info("Checking for existing GitLab data in volumes...")

        try:
            volumes_dir = docker_volumes_dir(self.remote)
            dir_check = self.remote.run(
                f"sudo test -d '{volumes_dir}' && echo 'exists' || echo 'missing'",
                check=False,
            )

            if "missing" in dir_check:
                print(f"   ❌ Docker volumes directory not found: {volumes_dir}")
                return None

            volumes_result = self.remote.run(
                f"sudo ls -la '{volumes_dir}/' 2>/dev/null | grep gitlab",
                check=False,
            )
            if not volumes_result:
                print("   ❌ No GitLab volumes found")
                return None

            print("   ✅ Found GitLab volumes:")
            for line in volumes_result.split("\n"):
                if "gitlab" in line and line.strip():
                    parts = line.strip().split()
                    print(f"     📦 {parts[-1] if parts else line.strip()}")

            # Try to get version from gitlab_data volume
            version_paths = [
                f"{volumes_dir}/gitlab_data/_data/gitlab-rails/VERSION",
                f"{volumes_dir}/gitlab_data/_data/opt/gitlab/embedded/service/gitlab-rails/VERSION",
                f"{volumes_dir}/gitlab_data/_data/var/opt/gitlab/gitlab-rails/VERSION",
            ]

            for path in version_paths:
                try:
                    result = self.remote.run(f"sudo cat '{path}' 2>/dev/null", check=False)
                    if result and result.strip():
                        m = re.search(r"(\d+\.\d+\.\d+)", result.strip())
                        if m:
                            version = m.group(1)
                            print(f"   📄 Found GitLab version {version} in {path}")
                            return version
                except Exception:
                    continue

            # Check for gitlab.rb config file (for hints)
            config_path = f"{volumes_dir}/gitlab_config/_data/gitlab.rb"
            try:
                result = self.remote.run(f"sudo cat '{config_path}' 2>/dev/null", check=False)
                if result and "external_url" in result:
                    print(f"   📄 Found GitLab config in {config_path}")
            except Exception:
                pass

            # DB presence = data exists (version unknown)
            try:
                db_result = self.remote.run(
                    f"sudo ls '{volumes_dir}/gitlab_data/_data/postgresql/' 2>/dev/null",
                    check=False,
                )
                if db_result:
                    print("   💾 Found PostgreSQL data - GitLab installation exists")
                    return "unknown_with_data"
            except Exception:
                pass

            print("   📁 Found GitLab volumes but version unknown")
            return "unknown_with_data"

        except Exception as e:
            print(f"   ⚠️  Error checking volumes: {e}")
            return None

    def _get_safe_starting_version(self, detected_version: Optional[str]) -> str:
        """
        Choose a conservative starting GitLab tag for **recovery** only (when data exists).
        Fresh installs do NOT use this function and deploy whatever is in GITLAB_IMAGE (often :latest).

        Rules:
          - 'unknown_with_data' or unparsable → start from 15.0.0 (conservative)
          - valid semantic version X.Y.Z       → start from that version
        """
        if not detected_version:
            return "15.0.0"

        if detected_version == "unknown_with_data":
            print("   🛡️  Unknown version but data exists - starting with GitLab 15.0.0")
            return "15.0.0"

        try:
            _major, _minor, _patch = map(int, detected_version.split("."))
            print(f"   🛡️  Starting with detected version: {detected_version}")
            return detected_version
        except Exception:
            return "15.0.0"

    # -------------------------- container helpers -----------------------

    def _detect_container_name(self) -> Optional[str]:
        """Detect a GitLab container name (running or exited)."""
        try:
            result = self.remote.run(
                "docker ps -a --format '{{.Names}}\\t{{.Image}}' | grep gitlab",
                check=False,
            )
            if not result:
                return None
            for line in result.strip().splitlines():
                if "\t" not in line:
                    continue
                name, image = line.split("\t", 1)
                if "gitlab" in image.lower():
                    return name.strip()
        except Exception:
            pass
        return None

    def _find_gitlab_container(self) -> Optional[str]:
        """Find any running GitLab container."""
        try:
            result = self.remote.run(
                "docker ps --format '{{.Names}}\\t{{.Image}}' | grep gitlab",
                check=False,
            )
            if result:
                lines = result.strip().split("\n")
                for line in lines:
                    if "\t" in line:
                        name, image = line.split("\t", 1)
                        if "gitlab" in image.lower():
                            return name.strip()
            return None
        except Exception:
            return None

    def _find_any_gitlab_container(self) -> Optional[tuple[str, str]]:
        """Find any GitLab container (running or stopped) and return (name, status)."""
        try:
            result = self.remote.run(
                "docker ps -a --format '{{.Names}}\\t{{.Image}}\\t{{.Status}}' | grep gitlab",
                check=False,
            )
            if result:
                lines = result.strip().split("\n")
                for line in lines:
                    if "\t" in line:
                        parts = line.split("\t")
                        if len(parts) >= 3:
                            name, image, status = parts[0], parts[1], parts[2]
                            if "gitlab" in image.lower():
                                if "Up" in status:
                                    return name.strip(), "running"
                                elif "Exited" in status:
                                    return name.strip(), "stopped"
            return None
        except Exception:
            return None

    def _stop_and_remove_gitlab_container(self):
        """Stop and remove any GitLab container before upgrade."""
        if not self.gitlab_container_name:
            return

        print(f"🛑 Stopping and removing GitLab container: {self.gitlab_container_name}")

        try:
            self.remote.run(f"docker stop {self.gitlab_container_name}", check=False)
            print(f"   Container {self.gitlab_container_name} stopped")
        except Exception:
            print(f"   Container {self.gitlab_container_name} was already stopped")

        try:
            self.remote.run(f"docker rm {self.gitlab_container_name}", check=False)
            print(f"   Container {self.gitlab_container_name} removed")
        except Exception:
            print(f"   Container {self.gitlab_container_name} was already removed")

    def _reconfigure_inside(self, container_name: str = "gitlab") -> None:
        """Run gitlab-ctl reconfigure inside the container (best effort)."""
        try:
            self.remote.run(
                f"docker exec -t {container_name} gitlab-ctl reconfigure",
                check=False,
            )
            self.remote.run(
                f"docker exec -t {container_name} gitlab-ctl restart nginx",
                check=False,
            )
        except Exception as e:
            print(f"⚠️  gitlab-ctl reconfigure failed (non-fatal): {e}")

    def _update_permissions(self, container_name: str = "gitlab") -> None:
        """Run update-permissions (best effort) — useful on recovered data."""
        try:
            self.remote.run(f"docker exec -t {container_name} update-permissions", check=False)
        except Exception:
            pass

    # ----------------------- Postgres incompat fix ----------------------

    def _parse_pg_major(self, s: str) -> Optional[int]:
        """
        Extract major number from '14' or 'PostgreSQL 16.10' kind of strings.
        For PG, '16.10' major is 16.
        """
        if not s:
            return None
        m = _PG_VERSION_RE.search(s)
        if not m:
            return None
        try:
            return int(m.group(1))
        except Exception:
            return None

    def _pg_versions(self, container: str) -> Tuple[Optional[int], Optional[int]]:
        data_major: Optional[int] = None
        server_major: Optional[int] = None

        try:
            out = self.remote.run(
                " ".join([
                    f"docker exec -t {container} bash -lc",
                    "\"set -e;",
                    "for f in",
                    "/var/opt/gitlab/postgresql/data/PG_VERSION",
                    "/var/opt/gitlab/postgresql/*/data/PG_VERSION;",
                    "do [ -f $f ] && echo $f; done | sort -V || true\"",
                ]),
                check=False,
            )
            paths = [p.strip() for p in out.splitlines() if p.strip()]
            if paths:
                majors = []
                for p in paths:
                    v = self.remote.run(
                        f"docker exec -t {container} bash -lc \"cat {p} 2>/dev/null || true\"",
                        check=False,
                    ).strip()
                    m = self._parse_pg_major(v)
                    if m:
                        majors.append(m)
                if majors:
                    data_major = max(majors)
        except Exception:
            pass

        # server
        try:
            out = self.remote.run(
                f"docker exec -t {container} bash -lc \"/opt/gitlab/embedded/bin/postgres -V 2>/dev/null || true\"",
                check=False,
            )
            server_major = self._parse_pg_major(out.strip())
        except Exception:
            pass

        return data_major, server_major


    def _pg_incompat_in_logs(self, container: str) -> bool:
        """Look for incompatibility pattern in Postgres current log."""
        try:
            out = self.remote.run(
                f"docker exec -t {container} bash -lc "
                f"\"(tail -n 2000 /var/log/gitlab/postgresql/current 2>/dev/null || true) | "
                f"grep -i 'incompatible with server' -m1 || true\"",
                check=False,
            )
            return bool(out.strip())
        except Exception:
            return False

    def _try_pg_upgrade(self, container: str) -> None:
        """
        Perform gitlab-ctl pg-upgrade safely:
          - stop heavy services (puma/sidekiq)
          - chown postgresql dir (just in case)
          - run pg-upgrade (VERBOSE=1)
          - reconfigure + restart
        """
        print("   🧰 Running gitlab-ctl pg-upgrade …")
        cmds = [
            f"docker exec -t {container} bash -lc 'gitlab-ctl stop puma || true'",
            f"docker exec -t {container} bash -lc 'gitlab-ctl stop sidekiq || true'",
            f"docker exec -t {container} bash -lc 'chown -R git:git /var/opt/gitlab/postgresql || true'",
            f"docker exec -t {container} bash -lc 'export VERBOSE=1; gitlab-ctl pg-upgrade'",
            f"docker exec -t {container} bash -lc 'gitlab-ctl reconfigure || true'",
            f"docker exec -t {container} bash -lc 'gitlab-ctl restart postgresql || true'",
            f"docker exec -t {container} bash -lc 'gitlab-ctl restart || true'",
        ]
        for c in cmds:
            self.remote.run(c, check=False)

    def _auto_fix_pg_incompat(self, container: str) -> None:
        """
        Detect and auto-fix Postgres major incompatibility.
        Triggers pg-upgrade if:
          - server_major > data_major (clear mismatch), OR
          - logs show 'database files are incompatible with server'
        """
        data_major, server_major = self._pg_versions(container)

        need = False
        reason = ""
        if server_major and data_major and server_major > data_major:
            need = True
            reason = f"PG {data_major} → {server_major}"
        elif self._pg_incompat_in_logs(container):
            need = True
            reason = "log shows incompatibility"

        if need:
            print(f"   🔧 Detected PG major incompatibility ({reason}). Executing pg-upgrade…")
            self._try_pg_upgrade(container)
        else:
            print("   ✅ No PG major incompatibility detected")

    # ------------------------------ run flow -----------------------------

    def _check_gitlab_status(self):
        """Check GitLab container status and determine action needed."""
        print("🔍 Checking GitLab container status...")

        container_info = self._find_any_gitlab_container()

        if container_info:
            name, status = container_info
            self.gitlab_container_name = name

            if status == "running":
                print(f"✅ Found running GitLab container: {name}")
                return "running"
            elif status == "stopped":
                print(f"🔴 Found stopped GitLab container: {name}")
                print("❌ ERROR: Cannot upgrade GitLab when it's not running!")
                print("   GitLab must be running to determine the current version via API.")
                print("   Please start GitLab first:")
                print(f"     docker start {name}")
                print("   Then run the upgrade again.")
                sys.exit(1)

        detected_version = self._detect_version_from_volumes()
        if detected_version:
            print("🔄 Found existing GitLab data but no running container")
            print("   This looks like a Docker Engine reinstallation scenario")
            return "recovery"

        print("❌ No GitLab container or data found")
        return "none"

    # -------------------------- volumes ensure --------------------------

    def _ensure_volumes_exist(self):
        """Create any missing volumes before running compose."""
        print("🔧 Ensuring all required volumes exist...")

        required_volumes = ["gitlab_config", "gitlab_logs", "gitlab_data"]

        handler = getattr(self.compose, "ssl_handler", None)
        handler_named = bool(handler and getattr(handler, "using_named_volume", False))
        using_named_ssl = (not GITLAB_SSL_BIND) or handler_named

        if using_named_ssl:
            if "gitlab_ssl" not in required_volumes:
                required_volumes.append("gitlab_ssl")
            reason = "handler fallback" if handler_named else "no bind-mount"
            print(f"   SSL: using named volume gitlab_ssl ({reason})")

        try:
            existing_volumes = self.remote.run(
                "docker volume ls --format '{{.Name}}'"
            ).split("\n")
            existing_volumes = [v.strip() for v in existing_volumes if v.strip()]
        except Exception:
            existing_volumes = []

        for volume_name in required_volumes:
            if volume_name not in existing_volumes:
                print(f"   Creating missing volume: {volume_name}")
                self.remote.run(f"docker volume create {volume_name}")
            else:
                print(f"   Volume exists: {volume_name}")

    # ------------------------------ main run ----------------------------

    def _install_docker_if_needed(self):
        """Install Docker Engine and Compose plugin if not present."""
        print("🔍 Checking Docker installation...")

        try:
            self.remote.run("docker --version")
            print("✅ Docker Engine is already installed")
            try:
                self.remote.run("docker compose version")
                print("✅ Docker Compose plugin is already installed")
                return
            except Exception:
                print("⚠️  Docker Compose plugin not found, will install it")
        except Exception:
            print("❌ Docker not found, installing Docker Engine...")

        print("📦 Installing Docker Engine...")
        install_commands = [
            "sudo apt-get remove -y docker docker-engine docker.io containerd runc || true",
            "sudo apt-get update",
            "sudo apt-get install -y ca-certificates curl gnupg lsb-release",
            "sudo mkdir -p /etc/apt/keyrings",
            "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg",
            'echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null',
            "sudo apt-get update",
            "sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin",
            f"sudo usermod -aG docker {self.remote.user}",
            "sudo systemctl enable docker",
            "sudo systemctl start docker",
        ]

        for cmd in install_commands:
            print(f"   Running: {cmd}")
            try:
                self.remote.run(cmd)
            except Exception as e:
                print(f"   ⚠️  Command failed but continuing: {e}")

        print("✅ Docker installation completed")
        print("📝 Note: You may need to log out and back in for group changes to take effect")

        try:
            result = self.remote.run("docker --version")
            print(f"   Docker version: {result.strip()}")
            result = self.remote.run("docker compose version")
            print(f"   Docker Compose version: {result.strip()}")
        except Exception as e:
            print(f"⚠️  Verification failed: {e}")

    def run(self, ladder: List[str]):
        # Ensure Docker present
        self._install_docker_if_needed()

        # Ensure TLS assets exist BEFORE any compose work
        if getattr(self.compose, "ssl_handler", None):
            try:
                self.compose.ssl_handler.ensure_ready(GITLAB_HOSTNAME)
                print(
                    f"🔐 TLS ready for {GITLAB_HOSTNAME} (bind: /home/{UBUNTU_USER}/gitlab/config/ssl)"
                )
            except Exception as e:
                print(f"⚠️  TLS preparation failed (continuing): {e}")

        # Check current GitLab status
        status = self._check_gitlab_status()

        if status == "running":
            current = self.probe.version() or "unknown"
            print(f"Connected. GitLab currently {current}\n")
            self.compose.ensure()
            self.compose.ps()
            try:
                current = self.probe.version() or "unknown"
                if current != "unknown":
                    self.compose.pin_latest_to(current)
            except Exception as e:
                print(f"⚠️  Could not pin :latest to current version: {e}")

        elif status == "recovery":
            print("🔄 RECOVERY MODE: Existing GitLab data detected")
            detected_version = self._detect_version_from_volumes()
            safe_version = self._get_safe_starting_version(detected_version)
            print(f"   Will start with GitLab {safe_version} to match existing data")

            self.compose.ensure()

            print(f"🔧 Starting GitLab {safe_version} to initialize with existing data…")

            edition = (
                self.compose._detect_edition()
                if hasattr(self.compose, "_detect_edition")
                else "ce"
            )
            if edition not in ("ce", "ee"):
                edition = "ce"

            self.puller.pull(self.remote, safe_version, edition=edition)
            self.compose.replace_tag(safe_version)

            cmp_cmd = self.compose._compose_cmd()

            # best-effort permissions pre-fix
            cname = self.gitlab_container_name or self._detect_container_name() or "gitlab"
            self._update_permissions(cname)

            self.remote.run(f"cd {self.compose.compose_dir} && {cmp_cmd} up -d")

            # refresh name in case it changed
            self.gitlab_container_name = self._detect_container_name() or self.gitlab_container_name or "gitlab"

            # --- NEW: auto fix PG incompat immediately after start
            self._auto_fix_pg_incompat(self.gitlab_container_name)

            # wait PG → reconfigure → healthy
            try:
                self.probe.wait_postgres_ready(self.gitlab_container_name, timeout_s=300)
            except Exception:
                pass

            self._reconfigure_inside(self.gitlab_container_name)

            print("    waiting for GitLab to initialize with existing data…", end="", flush=True)
            self.probe.wait_healthy(safe_version)
            self.probe.wait_migrations_done(self.gitlab_container_name)
            print(" OK")

            actual_version = self.probe.version()
            if actual_version and actual_version != safe_version:
                print(f"✅ GitLab initialized. Actual version: {actual_version}")
                from .upgrade_path import write_upgrade_path

                try:
                    if write_upgrade_path() > 0:
                        ladder = pathlib.Path("upgrade_path.txt").read_text().splitlines()
                        print(f"📋 Continuing with upgrade path: {len(ladder)} steps")
                    else:
                        ladder = []
                        print("✅ GitLab is already up-to-date after recovery")
                except Exception as e:
                    print(f"⚠️  Could not rebuild upgrade path: {e}")
                    ladder = []

        elif status == "none":
            print("No GitLab installation found. Will perform fresh installation.\n")
            self.compose.ensure()

        # Ensure all required volumes exist (after ensure/scaffold)
        self._ensure_volumes_exist()

        edition = "ce"
        try:
            if hasattr(self.compose, "_detect_edition"):
                edition = self.compose._detect_edition()
        except Exception:
            pass
        if edition not in ("ce", "ee"):
            edition = "ce"

        # -------- Registry health check (Docker Hub) --------
        if ladder:
            skip = os.getenv("GITLAB_SKIP_REGISTRY_CHECK", "").lower() in ("1", "true", "yes")
            if not skip:
                repo = f"gitlab/gitlab-{edition}"
                print(f"🌐 Checking Docker Hub availability for '{repo}' …", end="", flush=True)
                try:
                    if not self.puller.hub_healthy(self.remote, repo=repo, timeout=6):
                        print(" FAIL")
                        print("❌ Docker Hub appears unavailable (registry/token service).")
                        print("   Aborting upgrade to avoid partial stop. Try again later "
                              "or set GITLAB_SKIP_REGISTRY_CHECK=1 to bypass.")
                        self.remote.close()
                        return
                    else:
                        print(" OK")
                except Exception as e:
                    print(" WARN")
                    print(f"⚠️  Could not verify Docker Hub health ({e}); continuing cautiously.")

        # -------------------------- upgrade loop -------------------------

        if ladder:
            cmp_cmd = self.compose._compose_cmd()

            # record starting version once (if detectable)
            try:
                current_before = self.probe.version() or None
                self._persist_started_version_once(current_before)
            except Exception:
                pass

            for step, tag in enumerate(ladder, 1):
                print(f"▶  Step {step}/{len(ladder)}  →  {tag}")
                self.puller.pull(self.remote, tag, edition=edition)
                self.compose.replace_tag(tag)

                # Stop/remove old container before starting new one
                self._stop_and_remove_gitlab_container()

                # Start the new container
                self.remote.run(f"cd {self.compose.compose_dir} && {cmp_cmd} up -d")

                # refresh container name
                self.gitlab_container_name = self._detect_container_name() or self.gitlab_container_name or "gitlab"

                # --- NEW: auto fix PG incompat right after each start
                self._auto_fix_pg_incompat(self.gitlab_container_name)

                # Wait PG first for clearer DB failures, then full health
                try:
                    self.probe.wait_postgres_ready(self.gitlab_container_name, timeout_s=300)
                except Exception:
                    pass

                print("    waiting for GitLab to become healthy …", end="", flush=True)
                try:
                    self.probe.wait_healthy(tag)
                    print(" OK")
                except Exception:
                    print("\n   ⚠️ health timeout — trying pg-upgrade as a last resort")
                    self._auto_fix_pg_incompat(self.gitlab_container_name or "gitlab")
                    self.probe.wait_postgres_ready(self.gitlab_container_name or "gitlab", timeout_s=300)
                    print("    re-waiting health …", end="", flush=True)
                    self.probe.wait_healthy(tag)
                    print(" OK")

                # ── WAIT FOR DB MIGRATIONS (schema + background) ─────────────────────
                try:
                    name = self.gitlab_container_name or "gitlab"

                    try:
                        self.remote.run(
                            f"docker exec -t {name} bash -lc "
                            "'for i in $(seq 1 30); do /opt/gitlab/embedded/bin/pg_isready -q -d postgres && exit 0; sleep 2; done; exit 1'",
                            check=False,
                        )
                    except Exception:
                        pass

                    self.probe.wait_migrations_done(name, timeout_s=7200, poll=30)

                    self.remote.run(
                        f"docker exec -t {name} bash -lc "
                        "\"gitlab-rake gitlab:background_migrations:status | egrep '^(queued|active|retrying|paused)' || "
                        "echo 'No pending background migrations'\"",
                        check=False
                    )
                except Exception as e:
                    raise RuntimeError(f"Background migrations did not finish: {e} from e")

                # Reconfigure to ensure OMNIBUS TLS block applied on this step too
                self._reconfigure_inside(self.gitlab_container_name)

                # persist current successful version
                try:
                    self._persist_current_version(tag)
                except Exception:
                    pass

        self.remote.close()
        print("\n✔  Upgrade complete!")
