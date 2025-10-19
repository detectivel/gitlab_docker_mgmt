from __future__ import annotations
import pathlib, sys, re, json
from typing import List, Optional
from .ssh_client import SSH
from .docker_compose import ComposeScaffolder
from .docker_pull import Puller
from .gitlab_probe import GitLabProbe
from .vars import GITLAB_HOSTNAME, GITLAB_SSL_BIND  # <-- добавили

class Upgrader:
    """Coordinates Compose scaffolding, pulls, and health checks."""

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
        self.gitlab_container_name = None

    def _detect_version_from_volumes(self) -> Optional[str]:
        """Try to detect GitLab version from existing volume data"""
        print("🔍 Checking for existing GitLab data in volumes...")

        try:
            volumes_dir = "/var/lib/docker/volumes"
            dir_check = self.remote.run(f"sudo test -d {volumes_dir} && echo 'exists' || echo 'missing'", check=False)

            if "missing" in dir_check:
                print(f"   ❌ Docker volumes directory not found: {volumes_dir}")
                return None

            volumes_result = self.remote.run(f"sudo ls -la {volumes_dir}/ 2>/dev/null | grep gitlab", check=False)
            if not volumes_result:
                print("   ❌ No GitLab volumes found")
                return None

            print("   ✅ Found GitLab volumes:")
            for line in volumes_result.split('\n'):
                if 'gitlab' in line and line.strip():
                    print(f"     📦 {line.strip().split()[-1] if line.strip().split() else line.strip()}")

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
                        m = re.search(r'(\d+\.\d+\.\d+)', result.strip())
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
                if result and 'external_url' in result:
                    print(f"   📄 Found GitLab config in {config_path}")
            except Exception:
                pass

            # DB presence = data exists (version unknown)
            try:
                db_result = self.remote.run(f"sudo ls {volumes_dir}/gitlab_data/_data/postgresql/ 2>/dev/null", check=False)
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
        """Get a safe GitLab version to start with based on detected data"""
        if not detected_version:
            return "17.5.3"  # safe latest for fresh install

        if detected_version == "unknown_with_data":
            print("   🛡️  Unknown version but data exists - starting with GitLab 15.0.0")
            return "15.0.0"

        try:
            _major, _minor, _patch = map(int, detected_version.split('.'))
            print(f"   🛡️  Starting with detected version: {detected_version}")
            return detected_version
        except:
            return "15.0.0"  # conservative fallback

    def _install_docker_if_needed(self):
        """Install Docker Engine and Compose plugin if not present"""
        print("🔍 Checking Docker installation...")

        try:
            self.remote.run("docker --version")
            print("✅ Docker Engine is already installed")
            try:
                self.remote.run("docker compose version")
                print("✅ Docker Compose plugin is already installed")
                return
            except:
                print("⚠️  Docker Compose plugin not found, will install it")
        except:
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

    def _ensure_volumes_exist(self):
        """Create any missing volumes before running compose"""
        print("🔧 Ensuring all required volumes exist...")

        required_volumes = ['gitlab_config', 'gitlab_logs', 'gitlab_data']

        # ДО: всегда добавляли gitlab_ssl, что мешало bind-mount'у
        # ТЕПЕРЬ: добавляем gitlab_ssl ТОЛЬКО если используем именованный том (не bind)
        handler = getattr(self.compose, 'ssl_handler', None)
        handler_named = bool(handler and getattr(handler, 'using_named_volume', False))
        using_named_ssl = (not GITLAB_SSL_BIND) or handler_named

        if using_named_ssl:
            if 'gitlab_ssl' not in required_volumes:
                required_volumes.append('gitlab_ssl')
            reason = "handler fallback" if handler_named else "no bind-mount"
            print(f"   SSL: using named volume gitlab_ssl ({reason})")

        try:
            existing_volumes = self.remote.run("docker volume ls --format '{{.Name}}'").split('\n')
            existing_volumes = [v.strip() for v in existing_volumes if v.strip()]
        except:
            existing_volumes = []

        for volume_name in required_volumes:
            if volume_name not in existing_volumes:
                print(f"   Creating missing volume: {volume_name}")
                self.remote.run(f"docker volume create {volume_name}")
            else:
                print(f"   Volume exists: {volume_name}")

    def _find_gitlab_container(self) -> Optional[str]:
        """Find any running GitLab container"""
        try:
            result = self.remote.run("docker ps --format '{{.Names}}\t{{.Image}}' | grep gitlab", check=False)
            if result:
                lines = result.strip().split('\n')
                for line in lines:
                    if '\t' in line:
                        name, image = line.split('\t', 1)
                        if 'gitlab' in image.lower():
                            return name.strip()
            return None
        except:
            return None

    def _find_any_gitlab_container(self) -> Optional[tuple[str, str]]:
        """Find any GitLab container (running or stopped) and return (name, status)"""
        try:
            result = self.remote.run("docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' | grep gitlab", check=False)
            if result:
                lines = result.strip().split('\n')
                for line in lines:
                    if '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            name, image, status = parts[0], parts[1], parts[2]
                            if 'gitlab' in image.lower():
                                if 'Up' in status:
                                    return name.strip(), "running"
                                elif 'Exited' in status:
                                    return name.strip(), "stopped"
            return None
        except:
            return None

    def _stop_and_remove_gitlab_container(self):
        """Stop and remove any GitLab container before upgrade"""
        if not self.gitlab_container_name:
            return

        print(f"🛑 Stopping and removing GitLab container: {self.gitlab_container_name}")

        try:
            self.remote.run(f"docker stop {self.gitlab_container_name}", check=False)
            print(f"   Container {self.gitlab_container_name} stopped")
        except:
            print(f"   Container {self.gitlab_container_name} was already stopped")

        try:
            self.remote.run(f"docker rm {self.gitlab_container_name}", check=False)
            print(f"   Container {self.gitlab_container_name} removed")
        except:
            print(f"   Container {self.gitlab_container_name} was already removed")

    def _check_gitlab_status(self):
        """Check GitLab container status and determine action needed"""
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

    def _reconfigure_inside(self, container_name: str = "gitlab"):
        """Run gitlab-ctl reconfigure inside the container (best effort)."""
        try:
            self.remote.run(f"docker exec -t {container_name} gitlab-ctl reconfigure", check=False)
            self.remote.run(f"docker exec -t {container_name} gitlab-ctl restart nginx", check=False)
        except Exception as e:
            print(f"⚠️  gitlab-ctl reconfigure failed (non-fatal): {e}")

    def run(self, ladder: List[str]):
        # Ensure Docker present
        self._install_docker_if_needed()

        # Ensure TLS assets exist (and permissions) BEFORE any compose work
        if getattr(self.compose, "ssl_handler", None):
            try:
                self.compose.ssl_handler.ensure_ready(GITLAB_HOSTNAME)
                print(f"🔐 TLS ready for {GITLAB_HOSTNAME} (bind: /home/ubuntu/gitlab/config/ssl)")
            except Exception as e:
                print(f"⚠️  TLS preparation failed (continuing): {e}")

        # Check current GitLab status
        status = self._check_gitlab_status()

        if status == "running":
            current = self.probe.version() or "unknown"
            print(f"Connected. GitLab currently {current}\n")
            self.compose.ensure()
            self.compose.ps()

        elif status == "recovery":
            print("🔄 RECOVERY MODE: Existing GitLab data detected")
            detected_version = self._detect_version_from_volumes()
            safe_version = self._get_safe_starting_version(detected_version)
            print(f"   Will start with GitLab {safe_version} to match existing data")

            self.compose.ensure()

            print(f"🔧 Starting GitLab {safe_version} to initialize with existing data...")
            edition = self.compose._detect_edition() if hasattr(self.compose, '_detect_edition') else 'ce'

            self.puller.pull(self.remote, safe_version)
            self.compose.replace_tag(safe_version)

            cmp_cmd = self.compose._compose_cmd()
            self.remote.run(f"cd {self.compose.compose_dir} && {cmp_cmd} up -d")

            print("    waiting for GitLab to initialize with existing data…", end="", flush=True)
            self.probe.wait_healthy(safe_version)
            print(" OK")

            # Reconfigure to ensure TLS/nginx applied
            self._reconfigure_inside()

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

        # Perform upgrades if we have a ladder
        if ladder:
            cmp_cmd = self.compose._compose_cmd()

            for step, tag in enumerate(ladder, 1):
                print(f"▶  Step {step}/{len(ladder)}  →  {tag}")
                self.puller.pull(self.remote, tag)
                self.compose.replace_tag(tag)

                # Stop/remove old container before starting new one
                self._stop_and_remove_gitlab_container()

                # Start the new container
                self.remote.run(f"cd {self.compose.compose_dir} && {cmp_cmd} up -d")
                print("    waiting for GitLab to become healthy …", end="", flush=True)
                self.probe.wait_healthy(tag)
                print(" OK")

                # Reconfigure to ensure OMNIBUS TLS block applied on this step too
                self._reconfigure_inside()

        self.remote.close()
        print("\n✔  Upgrade complete!")
