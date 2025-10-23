# docker_compose.py

from __future__ import annotations

import json
import os
import re
import tempfile
from urllib.parse import urlparse
from .vars import ALLOWED_SUBNET

try:  # pragma: no cover - import resolution depends on execution context
    from .ssh_client import SSH
    from .utils import _replace_tag_sed
    from .vars import (
        GITLAB_CONTAINER_NAME,
        GITLAB_HOSTNAME,
        GITLAB_HTTP_PORT,
        GITLAB_HTTPS_ALT_PORT,
        GITLAB_HTTPS_PORT,
        GITLAB_IMAGE,
        GITLAB_RESTART_POLICY,
        GITLAB_SSL_BIND,
        GITLAB_SSL_HOST_DIR,
        GITLAB_HOSTNAME_FROM_ENV,
    )
except ImportError:  # pragma: no cover
    from ssh_client import SSH  # type: ignore
    from utils import _replace_tag_sed  # type: ignore
    from vars import (  # type: ignore
        GITLAB_CONTAINER_NAME,
        GITLAB_HOSTNAME,
        GITLAB_HTTP_PORT,
        GITLAB_HTTPS_ALT_PORT,
        GITLAB_HTTPS_PORT,
        GITLAB_IMAGE,
        GITLAB_RESTART_POLICY,
        GITLAB_SSL_BIND,
        GITLAB_SSL_HOST_DIR,
        GITLAB_HOSTNAME_FROM_ENV,
    )


from .utils import get_logger

class ComposeScaffolder:
    def __init__(self, ssh_client: SSH, compose_dir: str, compose_file: str = "docker-compose.yml", ssl_handler=None):
        self.ssh_client = ssh_client
        self.compose_dir = compose_dir
        self.compose_file = f"{compose_dir.rstrip('/')}/{compose_file}"
        self.r = ssh_client
        self.ssl_handler = ssl_handler
        self.log = get_logger()

    def ensure(self):
        """Ensure docker-compose.yml exists, scaffold from running container if needed."""
        self.r.run(f"mkdir -p {self.compose_dir}")
        try:
            _, exit_status = self.r.run_with_status(f"test -f '{self.compose_file}'")
            if exit_status != 0:
                self.log.info("docker-compose.yml not found, scaffolding from running container...")
                self.scaffold_from_running_container()
            else:
                self.log.info(f"Found existing docker-compose.yml at {self.compose_file}")
        except Exception as e:
            self.log.warning(f"Error checking compose file: {e}")
            self.log.info("Attempting to scaffold from running container...")
            self.scaffold_from_running_container()

    def ps(self):
        try:
            cmp_cmd = self._compose_cmd()
            result = self.r.run(f"cd '{self.compose_dir}' && {cmp_cmd} ps")
            self.log.info(f"Current service status:\n{result}")
        except (RuntimeError, OSError, TimeoutError) as e:
            print(f"⚠️  Could not get service status: {e}")

    def _compose_cmd(self):
        """Get the docker compose command (handles both old and new syntax)."""
        try:
            _, exit_status = self.r.run_with_status("docker compose version")
            if exit_status == 0:
                return "docker compose"
        except (RuntimeError, OSError, TimeoutError) as err:
            self.log.debug(f"'docker compose' check failed: {err}")

        try:
            _, exit_status = self.r.run_with_status("docker-compose version")
            if exit_status == 0:
                return "docker-compose"
        except (RuntimeError, OSError, TimeoutError) as err:
            self.log.debug(f"'docker-compose' check failed: {err}")

        return "docker compose"

    # -------------------- helpers (version/shm) --------------------

    @staticmethod
    def _parse_gitlab_semver_from_image(image: str) -> tuple[int, int, int] | None:
        """
        Extract  MAJOR.MINOR.PATCH  from tags like:
          gitlab/gitlab-ce:18.2.8-ce.0
          registry.example/gitlab/gitlab-ee:18.0.0-ee.0
        Returns (major, minor, patch) or None if cannot parse.
        """
        # take part after the last colon
        if ":" not in image:
            return None
        tag = image.rsplit(":", 1)[1]
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", tag)
        if not m:
            return None
        return int(m.group(1)), int(m.group(2)), int(m.group(3))

    @classmethod
    def _needs_shm(cls, image: str) -> bool:
        """
        Add shm_size only for GitLab >= 18.0.0.
        """
        ver = cls._parse_gitlab_semver_from_image(image)
        if not ver:
            return False
        major, _minor, _patch = ver
        return major >= 17

    # -------------------- scaffold from running --------------------

    def scaffold_from_running_container(self, container_name: str = "gitlab"):
        """Create docker-compose.yml from a running container, using an explicit version tag."""
        container_name = container_name or GITLAB_CONTAINER_NAME or "gitlab"
        self.log.info(f"Inspecting running container: {container_name}")

        try:
            result = self.r.run(f"docker inspect {container_name}")
        except RuntimeError as e:
            self.log.error(f"Failed to inspect container {container_name}")
            self.log.error("Make sure GitLab container is running and named 'gitlab'")
            self.log.error("You can check with: docker ps")
            raise RuntimeError(f"Failed to inspect container {container_name}") from e

        container_info = json.loads(result)[0]
        image = self._get_actual_image_tag(container_info)
        self.log.info(f"Detected image: {image}")

        ports = container_info['NetworkSettings']['Ports']
        mounts = container_info['Mounts']
        env_vars = container_info['Config']['Env']

        self.log.info(f"Found {len(mounts)} volume mounts:")
        for m in mounts:
            self.log.debug(f"{m.get('Source','?')} -> {m.get('Destination','?')} (Type: {m.get('Type','?')})")

        self._create_missing_volumes(mounts)
        compose_content = self._build_compose_content(image, ports, mounts, env_vars)

        self._upload_text(self.compose_file, compose_content, suffix='.yml', label="compose")

        try:
            self.r.run(f"test -f '{self.compose_file}'")
            self.log.info(f"Created docker-compose.yml at {self.compose_file}")
        except Exception as err:
            raise RuntimeError(f"Failed to verify upload of {self.compose_file}") from err

    def _create_missing_volumes(self, mounts):
        """Create external volumes that don't exist yet."""
        self.log.info("Creating missing Docker volumes...")

        path2name = {
            '/etc/gitlab': 'gitlab_config',
            '/var/log/gitlab': 'gitlab_logs',
            '/var/opt/gitlab': 'gitlab_data',
        }

        required = set()
        for m in mounts:
            dest = m.get('Destination', '')
            if dest in path2name:
                required.add(path2name[dest])

        handler = self.ssl_handler
        handler_has_cert = bool(handler and getattr(handler, '_cert_file', None))
        handler_named = bool(handler and getattr(handler, 'using_named_volume', False))

        if handler_named:
            required.add('gitlab_ssl')
            self.log.info("SSL handler requires gitlab_ssl named volume")
        elif handler_has_cert:
            self.log.info(f"SSL bind-mount in use from {handler.cert_path} (no named volume)")
        elif not GITLAB_SSL_BIND:
            required.add('gitlab_ssl')
            self.log.info("Will include gitlab_ssl external volume (no bind-mount detected)")

        try:
            existing = self.r.run("docker volume ls --format '{{.Name}}'").splitlines()
            existing = [v.strip() for v in existing if v.strip()]
        except Exception as err:
            self.log.debug(f"Could not list docker volumes: {err}")
            existing = []

        for v in sorted(required):
            if v not in existing:
                self.log.info(f"Creating volume: {v}")
                self.r.run(f"docker volume create {v}")
            else:
                self.log.debug(f"Volume exists: {v}")

    def _get_actual_image_tag(self, container_info):
        """Resolve the precise tag for the running image, avoiding :latest if possible."""
        original_image = container_info['Config']['Image']
        image_id = container_info['Image']

        if ":latest" not in original_image and ":" in original_image:
            return original_image

        try:
            lines = self.r.run("docker images --no-trunc --format '{{.Repository}}:{{.Tag}}\t{{.ID}}'").splitlines()
        except (RuntimeError, OSError, TimeoutError):
            lines = []

        for line in lines:
            if '\t' not in line:
                continue
            tag, img_id = line.split('\t', 1)
            if image_id.startswith(img_id) or img_id.startswith(image_id[:12]):
                if ":latest" not in tag:
                    return tag

        version = self._extract_version_from_container(container_info)
        if version:
            edition = "ee" if "gitlab-ee" in original_image else "ce"
            return f"gitlab/gitlab-{edition}:{version}-{edition}.0"

        return original_image

    @staticmethod
    def _is_version_tag(image_tag):
        return bool(re.search(r':\d+\.\d+\.\d+', image_tag))

    @staticmethod
    def _extract_version_from_container(container_info):
        labels = container_info.get('Config', {}).get('Labels', {})
        if labels:
            for key in ['version', 'gitlab.version', 'org.label-schema.version']:
                if key in labels:
                    v = labels[key]
                    if re.match(r'\d+\.\d+\.\d+', v):
                        return v
        env = container_info.get('Config', {}).get('Env', [])
        for e in env:
            if "=" in e:
                k, v = e.split('=', 1)
                if 'VERSION' in k.upper() and re.match(r'\d+\.\d+\.\d+', v):
                    return v
        return None

    @staticmethod
    def _get_hostname_from_env(env_vars):
        """Extract hostname from GITLAB_OMNIBUS_CONFIG external_url or fall back to configured default."""
        for e in env_vars:
            if e.startswith('GITLAB_OMNIBUS_CONFIG='):
                cfg = e.split('=', 1)[1]
                m = re.search(r"external_url\s+['\"]([^'\"]+)['\"]", cfg)
                if m:
                    return urlparse(m.group(1)).hostname or GITLAB_HOSTNAME
        return GITLAB_HOSTNAME

    def _resolve_hostname(self, env_vars):
        """
        Decide which hostname to put into compose.
        Rule: if GITLAB_HOSTNAME is set in config, it wins. We only log the detected one.
        If not set, fall back to value parsed from container env.
        """
        if GITLAB_HOSTNAME:
            detected = self._get_hostname_from_env(env_vars)
            if detected and detected != GITLAB_HOSTNAME:
                self.log.info(f"Forcing hostname: {detected} -> {GITLAB_HOSTNAME}")
            return GITLAB_HOSTNAME
        return self._get_hostname_from_env(env_vars)

    def _build_compose_content(self, image, ports, mounts, env_vars):  # noqa: PLR0912, PLR0915
        """Build docker-compose.yml content from a running container, adding OMNIBUS TLS block."""
        hostname = self._resolve_hostname(env_vars)

        # external_url: use the one from container only if hostname matches,
        # otherwise build from configured hostname and alt port
        external_url = f"https://{hostname}:{GITLAB_HTTPS_ALT_PORT}"
        env_external_url = None
        for e in env_vars:
            if e.startswith('GITLAB_OMNIBUS_CONFIG='):
                cfg = e.split('=', 1)[1]
                m = re.search(r"external_url\s+['\"]([^'\"]+)['\"]", cfg)
                if m:
                    env_external_url = m.group(1)
                    break

        if env_external_url:
            parsed = urlparse(env_external_url)
            # preserve only if host matches our final hostname
            if parsed.hostname == hostname:
                external_url = env_external_url
            else:
                if GITLAB_HOSTNAME_FROM_ENV:
                    self.log.info(f"Ignoring container external_url host '{parsed.hostname}', using '{hostname}'")

        content = "services:\n"
        content += "  gitlab:\n"
        content += f"    image: {image}\n"
        content += "    container_name: gitlab\n"
        content += "    restart: always\n"
        content += f"    hostname: {hostname}\n"

        # ← shm_size: only for GitLab 18+
        if self._needs_shm(image):
            content += '    shm_size: "1g"\n'

        content += "    ports:\n"

        # dedupe ports
        port_map = set()
        if ports:
            for cport, host_bind in ports.items():
                if host_bind:
                    for b in host_bind:
                        hp = b.get('HostPort')
                        if hp:
                            port_map.add((int(hp), int(cport.split('/')[0])))
        for hp, cp in sorted(port_map):
            content += f'      - "{hp}:{cp}"\n'

        content += "\n    volumes:\n"
        path2name = {'/etc/gitlab': 'gitlab_config', '/var/log/gitlab': 'gitlab_logs', '/var/opt/gitlab': 'gitlab_data'}
        external_named = set()

        if mounts:
            for m in mounts:
                dest = m.get('Destination', '')
                if dest in path2name:
                    name = path2name[dest]
                    external_named.add(name)
                    content += f"      - {name}:{dest}\n"

        # SSL mount: prefer bind-mount if we have certs (or when GITLAB_SSL_BIND=True)
        handler = self.ssl_handler
        handler_has_cert = bool(handler and getattr(handler, '_cert_file', None))
        handler_named = bool(handler and getattr(handler, 'using_named_volume', False))

        if handler_has_cert:
            content += f"      - {handler.cert_path}:/etc/gitlab/ssl\n"
        elif handler_named:
            external_named.add('gitlab_ssl')
            content += "      - gitlab_ssl:/etc/gitlab/ssl\n"
        elif not GITLAB_SSL_BIND:
            external_named.add('gitlab_ssl')
            content += "      - gitlab_ssl:/etc/gitlab/ssl\n"
        else:
            content += f"      - {GITLAB_SSL_HOST_DIR}:/etc/gitlab/ssl\n"

        # OMNIBUS block with explicit TLS paths
        content += "\n    environment:\n"
        content += "      GITLAB_OMNIBUS_CONFIG: |\n"
        content += f"        external_url '{external_url}'\n"
        content += "        nginx['listen_https'] = true\n"
        content += "        nginx['redirect_http_to_https'] = true\n"
        content += f"        nginx['ssl_certificate'] = \"/etc/gitlab/ssl/{hostname}.crt\"\n"
        content += f"        nginx['ssl_certificate_key'] = \"/etc/gitlab/ssl/{hostname}.key\"\n"
        content += f"        gitlab_rails['monitoring_whitelist'] = ['127.0.0.0/8', '{ALLOWED_SUBNET}']\n"

        content += "\nnetworks:\n  default:\n    driver: bridge\n\n"

        if external_named:
            content += "volumes:\n"
            for name in sorted(external_named):
                content += f"  {name}:\n"
                content += "    external: true\n"
                content += f"    name: {name}\n"

        return content

    # -------------------- scaffold from template --------------------

    def scaffold_from_template(  # noqa: PLR0913, PLR0915
        self,
        image: str = None,
        hostname: str = None,
        http_port: int = None,
        https_port: int = None,
        https_alt_port: int = None,
        restart_policy: str = None,
    ):
        """Create a docker-compose.yml for a fresh GitLab installation (with OMNIBUS TLS)."""

        image = image or GITLAB_IMAGE
        hostname = hostname or GITLAB_HOSTNAME
        http_port = int(http_port or GITLAB_HTTP_PORT)
        https_port = int(https_port or GITLAB_HTTPS_PORT)
        https_alt_port = int(https_alt_port or GITLAB_HTTPS_ALT_PORT)
        restart_policy = restart_policy or GITLAB_RESTART_POLICY

        resolved_image = image
        try:
            last_part = image.split('/')[-1]
            needs_res = (':' not in last_part) or last_part.endswith(':latest') or image.endswith(':latest')
            if needs_res:
                self.log.info(f"Pulling image {image} to resolve concrete tag on remote host...")
                self.r.run(f"docker pull {image}")
                out = self.r.run(f"docker inspect --format '{{{{json .RepoTags}}}}' {image}")
                try:
                    tags = json.loads(out)
                    if isinstance(tags, list) and tags:
                        resolved_image = tags[0]
                        self.log.info(f"Resolved image {image} -> {resolved_image}")
                except Exception:
                    resolved_image = image
        except Exception as e:
            self.log.warning(f"Could not resolve image tag for {image}: {e}")
            resolved_image = image

        content = "\n"
        content += "services:\n"
        content += "  gitlab:\n"
        content += f"    image: {resolved_image}\n"
        content += "    container_name: ${GITLAB_CONTAINER_NAME}\n"
        content += "    hostname: ${GITLAB_HOSTNAME}\n"
        content += "    restart: ${GITLAB_RESTART_POLICY}\n"

        # ← shm_size: only for GitLab 18+
        if self._needs_shm(resolved_image):
            content += '    shm_size: "1g"\n'

        content += "    ports:\n"
        content += "      - \"${GITLAB_HTTP_PORT}:80\"\n"
        content += "      - \"${GITLAB_HTTPS_PORT}:443\"\n"
        content += "      - \"${GITLAB_HTTPS_ALT_PORT}:8443\"\n"
        content += "    volumes:\n"
        content += "      - gitlab_config:/etc/gitlab\n"
        content += "      - gitlab_logs:/var/log/gitlab\n"
        content += "      - gitlab_data:/var/opt/gitlab\n"

        has_cert = bool(self.ssl_handler and getattr(self.ssl_handler, '_cert_file', None))
        use_named_ssl = False
        if has_cert:
            content += f"      - {self.ssl_handler.cert_path}:/etc/gitlab/ssl\n"
        elif self.ssl_handler is not None:
            use_named_ssl = True
        elif GITLAB_SSL_BIND:
            content += f"      - {GITLAB_SSL_HOST_DIR}:/etc/gitlab/ssl\n"
        else:
            use_named_ssl = True

        if use_named_ssl:
            content += "      - gitlab_ssl:/etc/gitlab/ssl\n"

        # OMNIBUS TLS environment (explicit external_url + cert paths)
        content += "\n    environment:\n"
        content += "      GITLAB_OMNIBUS_CONFIG: |\n"
        content += "        external_url 'https://${GITLAB_HOSTNAME}:${GITLAB_HTTPS_ALT_PORT}'\n"
        content += "        nginx['listen_https'] = true\n"
        content += "        nginx['redirect_http_to_https'] = true\n"
        content += "        nginx['ssl_certificate'] = \"/etc/gitlab/ssl/${GITLAB_HOSTNAME}.crt\"\n"
        content += "        nginx['ssl_certificate_key'] = \"/etc/gitlab/ssl/${GITLAB_HOSTNAME}.key\"\n"
        content += "        gitlab_rails['monitoring_whitelist'] = ['127.0.0.0/8','${ALLOWED_SUBNET}']\n"

        content += "\nnetworks:\n  default:\n    driver: bridge\n\n"
        content += "volumes:\n"
        content += "  gitlab_config:\n"
        content += "  gitlab_logs:\n"
        content += "  gitlab_data:\n"

        if use_named_ssl:
            content += "  gitlab_ssl:\n"
            content += "    external: true\n"
            content += "    name: gitlab_ssl\n"

        env_content = (
            f"GITLAB_IMAGE={resolved_image}\n"
            f"GITLAB_CONTAINER_NAME={GITLAB_CONTAINER_NAME}\n"
            f"GITLAB_HOSTNAME={hostname}\n"
            f"GITLAB_HTTP_PORT={http_port}\n"
            f"GITLAB_HTTPS_PORT={https_port}\n"
            f"GITLAB_HTTPS_ALT_PORT={https_alt_port}\n"
            f"GITLAB_RESTART_POLICY={restart_policy}\n"
        )

        self._upload_text(self.compose_file, content, suffix='.yml', label="template compose")

        env_remote = f"{self.compose_dir.rstrip('/')}/.env"
        self._upload_text(env_remote, env_content, suffix='.env', label=".env")

        try:
            self.r.run(f"test -f '{self.compose_file}'")
            self.r.run(f"test -f '{env_remote}'")
            self.log.info(f"Created docker-compose.yml and .env at {self.compose_file} (template)")
        except Exception as err:
            raise RuntimeError(f"Failed to verify upload of {self.compose_file} or {env_remote}") from err

    # -------------------- misc --------------------

    def _detect_edition(self):
        try:
            result = self.r.run("docker inspect gitlab", check=False)
            if "gitlab-ee" in result:
                return "ee"
        except Exception as err:
            self.log.debug(f"Could not detect edition from 'docker inspect': {err}")
        return "ce"

    def replace_tag(self, tag: str):
        edition = self._detect_edition()
        self.r.run(_replace_tag_sed(self.compose_file, tag, edition))

    def _compose_has_latest(self) -> bool:
        """
        Return True if compose file still references :latest for GitLab image.
        Kept intentionally simple to avoid false positives.
        """
        try:
            _out, rc = self.r.run_with_status(
                f"grep -E \"\\bgitlab/gitlab-(ce|ee):latest\\b\" '{self.compose_file}'"
            )
            return rc == 0
        except Exception:
            return False

    def pin_latest_to(self, tag: str) -> None:
        """
        If docker-compose.yml uses :latest, rewrite it to an explicit version tag
        like :{tag}-<edition>.0. This must happen BEFORE any replace_tag() calls,
        otherwise :latest won't match our numeric-tag sed pattern.
        """
        if not tag or not self._compose_has_latest():
            return

        edition = self._detect_edition()
        sed = (
            "sed -i -E "
            f"\"s|(gitlab/gitlab-{edition}):latest|\\1:{tag}-{edition}.0|g\" "
            f"'{self.compose_file}'"
        )
        try:
            self.log.info(f"Pinning image ':latest' → '{tag}-{edition}.0' in {self.compose_file}")
            self.r.run(sed)
        except Exception as e:
            self.log.warning(f"Failed to pin :latest to {tag}-{edition}.0: {e}")

    def _upload_text(self, remote_path: str, text: str, *, suffix: str, label: str):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=suffix) as tmp:
            tmp.write(text)
            tmp.flush()
            self.log.debug(f"Uploading {label} to {remote_path}...")
            self.r.put_file(tmp.name, remote_path)
        os.unlink(tmp.name)
