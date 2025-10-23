# ssl_handler.py
from __future__ import annotations

from datetime import datetime
from typing import Dict, Optional
from contextlib import suppress
from typing import Tuple
from .ssh_client import SSH
from .vars import UBUNTU_USER
from .utils import get_logger


class SSLHandler:
    log = get_logger()
    """
    Keeps TLS assets for GitLab either in a bind-mounted host folder
    (/home/ubuntu/gitlab/config/ssl) or in a named volume (gitlab_ssl).
    Validates presence + expiry (>30 days) in any of these locations.

    In-container path: /etc/gitlab/ssl
    """

    def __init__(self, ssh_client: SSH):
        self.ssh = ssh_client
        self.cert_path = f"/home/{UBUNTU_USER}/gitlab/config/ssl"
        self._cert_file: Optional[str] = None
        self._key_file: Optional[str] = None
        self.using_named_volume: bool = False

    # ---------------- internal helpers ---------------- #

    def _run_with_status(self, cmd: str) -> Tuple[str, int]:
        if hasattr(self.ssh, "run_with_status"):
            out, rc = self.ssh.run_with_status(cmd)  # type: ignore[attr-defined]
            return out or "", rc
        wrapped = "set +e; " f"{cmd}; " "rc=$?; " "printf \"__RC__%d\" \"$rc\""
        out = self.ssh.run(wrapped, check=False)
        if "__RC__" in out:
            body, rc_str = out.rsplit("__RC__", 1)
            try:
                return body.rstrip("\n"), int(rc_str.strip())
            except Exception:
                return body.rstrip("\n"), 1
        return out.rstrip("\n"), 1

    def _exists(self, path: str, sudo: bool = False) -> bool:
        prefix = "sudo " if sudo else ""
        _, rc = self._run_with_status(f"{prefix}test -f '{path}'")
        return rc == 0

    @staticmethod
    def _needs_passwordless_sudo(stderr: str) -> bool:
        """Return True when stderr looks like sudo prompting for a password."""
        lowered = stderr.lower()
        return any(
            token in lowered
            for token in (
                "a terminal is required to read the password",
                "a password is required",
                "sudo: no tty present",
                "sudo: password is required",
            )
        )

    def _run_with_sudo_fallback(self, cmd: str, *, check: bool = True) -> str:
        """Run *cmd* preferring sudo but gracefully fall back when sudo prompts."""
        sudo_cmd = f"sudo {cmd}"
        stdout, stderr, rc = self.ssh.run_full(sudo_cmd)
        if rc == 0:
            return stdout.strip()
        if self._needs_passwordless_sudo(stderr):
            self.log.info("Passwordless sudo unavailable; retrying without sudo")
            return self.ssh.run(cmd, check=check)
        if check:
            preview = self.ssh._preview(stderr) if hasattr(self.ssh, "_preview") else stderr
            raise RuntimeError(f"[{sudo_cmd}] failed (rc={rc}):\n{preview}")
        return stdout.strip()

    def _parse_not_after_days(self, crt_path: str, sudo: bool = False) -> Optional[int]:
        prefix = "sudo " if sudo else ""
        out, rc = self._run_with_status(f"{prefix}openssl x509 -in '{crt_path}' -noout -dates")
        if rc != 0 or not out:
            return None
        expiry_str = next(
            (line.split("notAfter=", 1)[1].strip() for line in out.splitlines() if "notAfter=" in line),
            None
        )
        if not expiry_str:
            return None
        try:
            expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            try:
                expiry = datetime.strptime(" ".join(expiry_str.split()), "%b %d %H:%M:%S %Y %Z")
            except Exception:
                return None
        return (expiry - datetime.now()).days

    def _find_gitlab_container(self) -> Optional[str]:
        out, rc = self._run_with_status("docker ps --format '{{.Names}}\\t{{.Image}}' | grep gitlab")
        if rc != 0 or not out:
            return None
        for line in out.strip().splitlines():
            if "\t" not in line:
                continue
            name, image = line.split("\t", 1)
            if "gitlab" in image.lower():
                return name.strip()
        return None

    def _container_has_valid_cert(self, domain: str) -> bool:
        name = self._find_gitlab_container()
        if not name:
            return False
        crt = f"/etc/gitlab/ssl/{domain}.crt"
        key = f"/etc/gitlab/ssl/{domain}.key"
        # test files
        _, rc1 = self._run_with_status(f"docker exec {name} test -f '{crt}'")
        _, rc2 = self._run_with_status(f"docker exec {name} test -f '{key}'")
        if rc1 != 0 or rc2 != 0:
            return False
        # check expiry (run openssl inside container)
        out, rc = self._run_with_status(f"docker exec {name} openssl x509 -in '{crt}' -noout -dates")
        if rc != 0 or not out:
            return False
        expiry_str = next(
            (line.split("notAfter=", 1)[1].strip() for line in out.splitlines() if "notAfter=" in line),
            None
        )
        if not expiry_str:
            return False
        try:
            expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            try:
                expiry = datetime.strptime(" ".join(expiry_str.split()), "%b %d %H:%M:%S %Y %Z")
            except Exception:
                return False
        days_left = (expiry - datetime.now()).days
        if days_left <= 30:
            return False
        # mark for callers
        self._cert_file = f"{self.cert_path}/{domain}.crt"
        self._key_file = f"{self.cert_path}/{domain}.key"
        return True

    def _gitlab_ssl_volume_mountpoint(self) -> Optional[str]:
        out, rc = self._run_with_status("docker volume inspect gitlab_ssl --format '{{.Mountpoint}}'")
        if rc != 0 or not out:
            return None
        mountpoint = out.strip()
        return mountpoint if mountpoint and mountpoint != "<no value>" else None

    def _volume_has_valid_cert(self, domain: str) -> bool:
        mount = self._gitlab_ssl_volume_mountpoint()
        if not mount:
            return False
        crt = f"{mount}/{domain}.crt"
        key = f"{mount}/{domain}.key"
        if not (self._exists(crt, sudo=True) and self._exists(key, sudo=True)):
            return False
        days_left = self._parse_not_after_days(crt, sudo=True)
        if days_left is None or days_left <= 30:
            return False
        # mark for callers (logical paths)
        self._cert_file = f"{self.cert_path}/{domain}.crt"
        self._key_file = f"{self.cert_path}/{domain}.key"
        return True

    # ---------------- public API ---------------- #

    def is_ssl_configured(self, domain: str) -> bool:
        """
        True if cert/key exist and are valid (>30 days) in ANY of:
        - host bind path (/home/ubuntu/gitlab/config/ssl)
        - inside running container (/etc/gitlab/ssl)              [preferred when running]
        - docker volume gitlab_ssl's mountpoint (via sudo)
        """
        # 1) host bind path
        host_crt = f"{self.cert_path}/{domain}.crt"
        host_key = f"{self.cert_path}/{domain}.key"
        if self._exists(host_crt) and self._exists(host_key):
            days_left = self._parse_not_after_days(host_crt)
            if days_left is not None and days_left > 30:
                self._cert_file, self._key_file = host_crt, host_key
                self.using_named_volume = False
                return True

        # 2) running container (covers named-volume case too)
        if self._container_has_valid_cert(domain):
            self.using_named_volume = False
            return True

        # 3) named volume mountpoint on host (if accessible)
        if self._volume_has_valid_cert(domain):
            self.using_named_volume = False
            return True

        return False

    def generate_self_signed_cert(self, domain: str, days: int = 825) -> tuple[str, str]:
        """
        Generate a self-signed cert/key under self.cert_path using sudo
        (works for bind-mount workflow). For named-volume users, prefer
        creating certs with docker exec or copying into the volume.
        """
        self._cert_file = f"{self.cert_path}/{domain}.crt"
        self._key_file  = f"{self.cert_path}/{domain}.key"

        self._run_with_sudo_fallback(f"mkdir -p {self.cert_path}", check=False)
        self._run_with_sudo_fallback(f"openssl genrsa -out {self._key_file} 2048")
        self._run_with_sudo_fallback(
            "openssl req -new -x509 "
            f"-key {self._key_file} "
            f"-out {self._cert_file} "
            f"-days {days} "
            f"-subj '/CN={domain}' "
            f"-addext 'subjectAltName=DNS:{domain}'"
        )
        self._run_with_sudo_fallback(f"chmod 600 {self._key_file}")
        self._run_with_sudo_fallback(f"chmod 644 {self._cert_file}")
        self._run_with_sudo_fallback(
            f"chown root:root {self._key_file} {self._cert_file}",
            check=False,
        )
        return self._cert_file, self._key_file

    def ensure_ready(self, domain: str, days: int = 825) -> Tuple[str, str]:
        cert = f"{self.cert_path}/{domain}.crt"
        key  = f"{self.cert_path}/{domain}.key"
        with suppress(OSError, RuntimeError, ValueError):
            if self.is_ssl_configured(domain):
                return cert, key
        try:
            return self.generate_self_signed_cert(domain, days=days)
        except Exception:
            self._cert_file = None
            self._key_file = None
            self.using_named_volume = True
            raise

    def get_ssl_volume_config(self) -> Dict[str, Dict]:
        if not self._cert_file or not self._key_file:
            return {}
        return {
            "gitlab_ssl": {
                "driver": "local",
                "driver_opts": {
                    "type": "none",
                    "o": "bind",
                    "device": self.cert_path,
                },
            }
        }

    def configure_gitlab_ssl(self, domain: str) -> None:
        """Compatibility stub — do not write gitlab.rb; compose handles nginx/tls."""
        self.ensure_ready(domain)
