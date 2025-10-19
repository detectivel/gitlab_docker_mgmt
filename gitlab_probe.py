from __future__ import annotations

import time
import re
import html
import paramiko
import requests
import urllib3

from .ssh_client import SSH
from .utils import get_logger

urllib3.disable_warnings()

_VERSION_RE = re.compile(r"GitLab\s+(\d+\.\d+\.\d+)")
HTTP_OK = 200


class GitLabProbe:
    """HTTP + Docker health probes for a GitLab instance."""

    def __init__(self, base_url: str, remote: SSH):
        # base_url must be like https://host:port without a trailing slash
        self.base_url = (base_url or "").rstrip("/")
        self.r = remote
        self.log = get_logger()

    # -------------------------- docker helpers -------------------------- #

    def _find_gitlab_container(self) -> str:
        """Find any running GitLab container name"""
        try:
            result = self.r.run(
                "docker ps --format '{{.Names}}\t{{.Image}}' | grep gitlab",
                check=False,
            )
            if result:
                for line in result.strip().splitlines():
                    if "\t" not in line:
                        continue
                    name, image = line.split("\t", 1)
                    if "gitlab" in image.lower():
                        return name.strip()
        except (RuntimeError, OSError, paramiko.SSHException) as err:
            self.log.debug("_find_gitlab_container error: %s", err)
        return "gitlab"  # fallback to the default name

    def _docker_health(self) -> str:
        container_name = self._find_gitlab_container()
        try:
            insp = self.r.run(
                f"docker inspect {container_name} --format '{{{{json .State.Health.Status}}}}'",
                check=False,
            )
            return insp.strip('"') if insp else "unknown"
        except (RuntimeError, OSError, paramiko.SSHException) as err:
            self.log.debug("docker health check failed: %s", err)
            return "unknown"

    # -------------------------- version helpers ------------------------- #

    def _container_version(self) -> str | None:
        """Read the version file inside the container."""
        container_name = self._find_gitlab_container()
        try:
            cmd = (
                f"docker exec {container_name} bash -lc "
                "'cat /opt/gitlab/embedded/service/gitlab-rails/VERSION 2>/dev/null'"
            )
            out = self.r.run(cmd, check=False)
            return out.strip() or None
        except (RuntimeError, OSError, paramiko.SSHException):
            return None

    def version(self) -> str | None:
        """
        Best-effort version discovery:
          1) /-/metadata  (GitLab 16+)
          2) VERSION file inside container
          3) /help page scraping
          4) /api/v4/version (may require auth; we try unauth)
        """
        # 1) /-/metadata
        try:
            res = requests.get(
                f"{self.base_url}/-/metadata",
                verify=False,  # self-signed during bootstrap # noqa: S501
                timeout=5,
            )
            if res.status_code == HTTP_OK:
                v = res.json().get("version")
                if v:
                    return v
        except requests.RequestException:
            pass

        # 2) container file
        v = self._container_version()
        if v:
            return v

        # 3) /help
        try:
            res = requests.get(
                f"{self.base_url}/help",
                verify=False,  # self-signed during bootstrap # noqa: S501
                timeout=5,
            )
            if res.status_code == HTTP_OK:
                m = _VERSION_RE.search(html.unescape(res.text))
                if m:
                    return m.group(1)
        except requests.RequestException:
            pass

        # 4) /api/v4/version
        try:
            res = requests.get(
                f"{self.base_url}/api/v4/version",
                verify=False,  # self-signed during bootstrap # noqa: S501
                timeout=5,
            )
            if res.status_code == HTTP_OK:
                return res.json().get("version")
        except requests.RequestException:
            pass

        return None

    # ----------------------------- wait_healthy -------------------------- #

    def wait_healthy(self, expect: str, timeout: int = 1800, stable: int = 3):
        """
        Waits up to `timeout` seconds until the instance becomes healthy
        and reports the expected version (prefix match).
        Requires `stable` consecutive successful checks.
        Prints a short status line; on timeout collects diagnostics.
        """
        deadline = time.monotonic() + timeout
        ok = 0
        backoff = 5
        max_backoff = 15

        print()

        while time.monotonic() < deadline:
            http_ok = False
            codes = []
            docker_flag = "-"

            # HTTP liveness/readiness
            for ep in ("liveness", "health", "readiness"):
                url = f"{self.base_url}/-/{ep}"
                try:
                    resp = requests.get(url, verify=False, timeout=5)  # noqa: S501
                    code = resp.status_code
                except requests.Timeout:
                    code = "TIMEOUT"
                except requests.RequestException as err:
                    self.log.debug("HTTP %s failed: %s", url, err)
                    code = "ERR"

                codes.append(code)
                if code == HTTP_OK:
                    http_ok = True
                    break

            if not http_ok and all(c in (404, "ERR") for c in codes):
                docker_flag = self._docker_health()
                http_ok = docker_flag == "healthy"

            ver = self.version() or "?"
            status = f"\rhttp={docker_flag if docker_flag != '-' else codes}  version={ver}  backoff={backoff:2d}s"
            print(status, end="", flush=True)

            version_ok = (ver != "?") and ver.startswith(str(expect))
            if http_ok and version_ok:
                ok += 1
                if ok >= stable:
                    print("\n      ↪ healthy, waiting 30 s for extra probes …", flush=True)
                    time.sleep(30)
                    return
            else:
                ok = 0

            time.sleep(backoff)
            if backoff < max_backoff:
                backoff = min(max_backoff, backoff + 1)

        # ---------- Timeout: collect diagnostics ----------
        print("\n❌ Timed out while waiting for GitLab to become healthy.")
        self._diagnostics(expect)

        raise TimeoutError(f"GitLab never reported healthy {expect} in {timeout}s")

    # ------------------------------ diagnostics -------------------------- #

    def _diagnostics(self, expect: str):
        """Collect useful logs and statuses to understand failures."""
        container = self._find_gitlab_container()

        def _hdr(title: str):
            print(f"\n—— {title} ——")

        try:
            _hdr("docker ps --format '{{.Names}} {{.Status}}' | grep gitlab")
            out = self.r.run("docker ps --format '{{.Names}}\t{{.Status}}' | grep gitlab",
                             check=False)
            print(out or "(no running gitlab container)")
        except (RuntimeError, OSError, paramiko.SSHException) as err:
            self.log.debug("diagnostic docker ps failed: %s", err)

        try:
            _hdr("docker inspect health")
            out = self.r.run(
                f"docker inspect {container} --format '{{{{json .State}}}}'",
                check=False,
            )
            print(out or "(no state)")
        except (RuntimeError, OSError, paramiko.SSHException) as err:
            self.log.debug("diagnostic docker inspect failed: %s", err)

        try:
            _hdr("gitlab-ctl status")
            out = self.r.run(f"docker exec -t {container} gitlab-ctl status", check=False)
            print(out)
        except (RuntimeError, OSError, paramiko.SSHException) as err:
            self.log.debug("diagnostic docker exec -t failed: %s", err)

        try:
            _hdr("nginx/error.log (tail -n 120)")
            cmd = (
                f"docker exec -t {container} bash -lc "
                "'tail -n 120 /var/log/gitlab/nginx/error.log 2>/dev/null'"
            )
            out = self.r.run(cmd, check=False)
            print(out or "(empty)")
        except (RuntimeError, OSError, paramiko.SSHException) as err:
            self.log.debug("diagnostic 'nginx' failed: %s", err)

        try:
            _hdr("reconfigure last lines (grep -n 'Starting Chef Infra Client')")
            cmd = (
                f"docker exec -t {container} bash -lc "
                "\"grep -n 'Starting Chef Infra Client' -n "
                "/var/log/gitlab/reconfigure/last_run.log 2>/dev/null || true; "
                'tail -n 80 /var/log/gitlab/reconfigure/last_run.log 2>/dev/null || true"'
            )
            out = self.r.run(cmd, check=False)
            print(out or "(no reconfigure log)")
        except (RuntimeError, OSError, paramiko.SSHException) as err:
            self.log.debug("diagnostic 'Starting Chef Infra Client' failed: %s", err)

        # final hint
        self.log.error(
            f"Timeout waiting for healthy version '{expect}'. Check TLS paths, OMNIBUS config, and container health."
        )
