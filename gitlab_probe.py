# gitlab_probe.py

from __future__ import annotations
import time
import shlex
import re
import html
import json
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


    def read_pg_data_version(self, name: str = "gitlab") -> str | None:
        """Return on-disk cluster PG_VERSION (e.g., '14', '15', '16') or None."""
        out = self.r.run(
            f"docker exec {name} bash -lc \"cat /var/opt/gitlab/postgresql/data/PG_VERSION 2>/dev/null || true\"",
            check=False,
            trace=False,
        )
        v = (out or "").strip()
        return v or None

    def ensure_pg16(self, name: str = "gitlab") -> bool:
        """
        Ensure the on-disk Postgres cluster is v16+. If lower, run a one-time pg-upgrade.
        Returns True if cluster is 16+ (already or after upgrade).
        """
        v = self.read_pg_data_version(name)
        if not v:
            return False  # can't detect -> let normal flow continue
        try:
            major = int(v.split(".", 1)[0])
        except ValueError:
            return False
        if major >= 16:
            return True

        # avoid repeat: set a flag file
        flag = "/var/opt/gitlab/.pg_upgrade_attempted"
        out, rc = self.r.run_with_status(
            f"docker exec {name} bash -lc \"test -f '{flag}'\"",
            trace=False,
        )
        if rc != 0:
            # permissive fixes and upgrade
            self.r.run(
                f"docker exec {name} update-permissions",
                check=False,
                trace=False,
            )
            self.r.run(
                f"docker exec {name} bash -lc "
                "\"chown -R gitlab-psql:gitlab-psql /var/opt/gitlab/postgresql && chmod 700 /var/opt/gitlab/postgresql\"",
                check=False,
                trace=False,
            )
            # run pg-upgrade (omnibus helper)
            self.r.run(
                f"docker exec -t {name} gitlab-ctl pg-upgrade",
                check=False,
                trace=False,
            )
            self.r.run(
                f"docker exec {name} bash -lc \"touch '{flag}'\"",
                check=False,
                trace=False,
            )
            # re-check
            v2 = self.read_pg_data_version(name)
            try:
                return v2 is not None and int(v2.split(".", 1)[0]) >= 16
            except Exception:
                return False
        return True

    def _find_gitlab_container(self) -> str:
        """Find any running GitLab container name (fallback 'gitlab')."""
        try:
            result = self.r.run(
                "docker ps --format '{{.Names}}\\t{{.Image}}' | grep gitlab",
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
                trace=False,
            )
            raw = (insp or "").strip()
            try:
                # might be plain "healthy" or quoted JSON string
                return json.loads(raw)
            except Exception:
                return raw.strip('"') or "unknown"
        except (RuntimeError, OSError, paramiko.SSHException) as err:
            self.log.debug("docker health check failed: %s", err)
            return "unknown"

    # -------------------------- PG quick helpers -------------------------- #

    def pg_status_ok(self, name: str = "gitlab") -> bool:
        """Return True if postgresql service is 'run:' in gitlab-ctl status."""
        out = self.r.run(
            f"docker exec -t {name} bash -lc \"gitlab-ctl status postgresql || true\"",
            check=False,
        ) or ""
        return "run:" in out

    def print_pg_tail(self, name: str = "gitlab", n: int = 120) -> None:
        """Print last N lines of PG logs (best effort)."""
        out = self.r.run(
            f"docker exec -t {name} bash -lc 'gitlab-ctl tail postgresql -n {n} 2>/dev/null || true'",
            check=False,
        )
        print(out or "(no postgresql logs)")

    def wait_postgres_ready(self, name: str = "gitlab", timeout_s: int = 120) -> None:
        """Wait until postgresql is reported as 'run:'; raise with tail if not."""
        import time

        start = time.time()
        while time.time() - start < timeout_s:
            if self.pg_status_ok(name):
                return
            time.sleep(3)

        # diagnostics before raising
        print("🔎 PostgreSQL didn't become ready in time. Tail:")
        self.print_pg_tail(name, n=200)
        raise RuntimeError("PostgreSQL did not become ready in time")

    def _rake(self, name: str, cmd: str) -> str:
        return self.r.run(f"docker exec -t {name} bash -lc {shlex.quote(cmd)}", check=False) or ""

    def background_migrations_pending(self, name: str = "gitlab") -> bool:
        out = self.r.run(
            f"docker exec -t {name} bash -lc "
            "'gitlab-rake gitlab:background_migrations:status || true'",
            check=False,
        ) or ""
        return bool(re.search(r'^(queued|active|retrying|paused)\b', out, re.MULTILINE))

    def wait_migrations_done(
            self,
            name: str = "gitlab",
            timeout_s: int = 7200,
            poll: int = 10,
            bgm_heartbeat_s: int = 60,
    ) -> None:
        start = time.time()
        deadline = start + timeout_s

        def _counts() -> tuple[int, int, int, int]:
            out = self.r.run(
                f"docker exec -t {name} bash -lc "
                "'gitlab-rake gitlab:background_migrations:status || true'",
                check=False,
            ) or ""
            q = len(re.findall(r'^queued\b', out, re.MULTILINE))
            a = len(re.findall(r'^active\b', out, re.MULTILINE))
            r = len(re.findall(r'^retrying\b', out, re.MULTILINE))
            p = len(re.findall(r'^paused\b', out, re.MULTILINE))
            return q, a, r, p

        try:
            self.r.run(
                f"docker exec -t {name} bash -lc "
                "'for i in $(seq 1 30); do /opt/gitlab/embedded/bin/pg_isready -q -d postgres && exit 0; sleep 2; done; exit 1'",
                check=False,
            )
        except Exception:
            pass

        # 1) schema migrations
        printed_wait = False
        while time.time() < deadline:
            if self.db_migrations_up(name):
                if printed_wait:
                    print("schema: OK")
                break
            if not printed_wait:
                print("schema: waiting for Rails migrations …")
                printed_wait = True
            time.sleep(poll)
        else:
            raise RuntimeError("timeout: Rails migrations didn’t finish")

        print("bgm: waiting for background migrations to complete …")
        last_counts: tuple[int, int, int, int] | None = None
        last_print_ts = 0.0

        while time.time() < deadline:
            q, a, r, p = _counts()
            now = time.time()
            changed = (last_counts is None) or (last_counts != (q, a, r, p))
            heartbeat = (now - last_print_ts) >= bgm_heartbeat_s

            if changed or heartbeat:
                elapsed = int(now - start)
                print(f"bgm: queued={q} active={a} retrying={r} paused={p}  elapsed={elapsed}s")
                last_counts = (q, a, r, p)
                last_print_ts = now

            if (q + a + r + p) == 0 and not self.background_migrations_pending(name):
                print("No pending background migrations")
                return

            time.sleep(poll)

        raise RuntimeError("timeout: background migrations didn’t finish")

    def db_migrations_up(self, name: str = "gitlab") -> bool:
        out = self.r.run(
            f"docker exec -t {name} bash -lc "
            "\"gitlab-rake gitlab:check SANITIZE=true | grep -F 'All migrations up? ... yes' || true\"",
            check=False,
        ) or ""
        return "All migrations up? ... yes" in out

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
                timeout=6,
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
                timeout=6,
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
                timeout=6,
            )
            if res.status_code == HTTP_OK:
                return res.json().get("version")
        except requests.RequestException:
            pass

        return None

    # ----------------------------- wait_healthy -------------------------- #

    def wait_healthy(
        self,
        expect_version: str | None,
        timeout: int = 1800,
        poll: int = 5,
        throttle_s: int = 30,
        compact: bool = True,
    ):
        import os
        import time

        is_jenkins = bool(os.getenv("JENKINS_URL") or os.getenv("BUILD_ID"))
        deadline = time.time() + timeout

        name = self._find_gitlab_container()

        version = "unknown"
        try:
            v = self.r.run(
                f"docker exec {name} bash -lc 'cat /opt/gitlab/embedded/service/gitlab-rails/VERSION 2>/dev/null'",
                check=False,
            )
            if v:
                version = v.strip()
        except Exception:
            pass

        last_line = None
        last_print_ts = 0.0

        while time.time() < deadline:
            raw = self.r.run(
                f"docker inspect {name} --format '{{{{json .State.Health.Status}}}}'",
                check=False,
                trace=False,
            ).strip()
            try:
                health = json.loads(raw)
            except Exception:
                health = (raw or "").strip('"') or "unknown"

            line = f"http={health:<8}  version={version}"

            now = time.time()
            should_print = (line != last_line) or ((now - last_print_ts) >= throttle_s)

            if compact and not is_jenkins:
                if should_print:
                    print(f"\r{line}", end="", flush=True)
                    last_line = line
                    last_print_ts = now
            else:
                if should_print:
                    print(line)
                    last_line = line
                    last_print_ts = now

            if health == "healthy":
                if compact and not is_jenkins:
                    print()
                return

            time.sleep(max(1, int(poll)))

        if compact and not is_jenkins:
            print()  # finish the line nicely
        raise RuntimeError("timeout: GitLab did not become healthy")

    # ------------------------------ diagnostics -------------------------- #

    def _diagnostics(self, expect: str):
        """Collect useful logs and statuses to understand failures."""
        container = self._find_gitlab_container()

        def _hdr(title: str):
            print(f"\n—— {title} ——")

        try:
            _hdr("docker ps --format '{{.Names}} {{.Status}}' | grep gitlab")
            out = self.r.run(
                "docker ps --format '{{.Names}}\\t{{.Status}}' | grep gitlab",
                check=False,
            )
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
            out = self.r.run(
                f"docker exec -t {container} gitlab-ctl status",
                check=False,
            )
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
