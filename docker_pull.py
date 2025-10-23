from __future__ import annotations

import re
import time
import urllib.parse
from .ssh_client import SSH
from .utils import get_logger

# thresholds / tuning
MIN_SPEED_MB = 1.0          # minimum sustained speed (MB/s) before we consider it “slow”
SLOW_STREAK  = 15           # how many consecutive seconds of “slow” before restarting
MAX_RETRIES  = 3            # max retries for poor network / transient failures
STALL_SECS   = 30           # if there is no output for N seconds — treat as “stalled” and retry

# speed like: "12.3 MB/s", "900 kB/s", "12345 B/s"
_SPEED_RE = re.compile(r"([0-9.]+)\s*([kM]?)(?:B|Byte)/s", re.I)


class Puller:
    """`docker pull` with speed/stall watchdog and edition detection."""

    def __init__(
        self,
        min_speed_mb: float = MIN_SPEED_MB,
        slow_streak: int = SLOW_STREAK,
        max_retries: int = MAX_RETRIES,
        stall_secs: int = STALL_SECS,
    ):
        self.min_speed_mb = float(min_speed_mb)
        self.slow_streak = int(slow_streak)
        self.max_retries = int(max_retries)
        self.stall_secs = int(stall_secs)
        self.log = get_logger()

    @staticmethod
    def hub_healthy(self, remote: "SSH", repo: str = "gitlab/gitlab-ce", timeout: int = 5) -> bool:
        """
        Docker Hub liveness:
          1) /v2/ should be reachable (200 or 401 are OK)
          2) token service for repo scope should return 200
        """
        code1_out, _ = remote.run_with_status(
            " ".join([
                "curl -sS",
                f"--connect-timeout {timeout}",
                f"--max-time {timeout}",
                "-o /dev/null",
                r"-w '%{http_code}'",
                "https://registry-1.docker.io/v2/",
                "|| echo 000"
            ])
        )
        out1 = (code1_out or "").strip()
        ok1 = out1 in ("200", "401")

        # 2) token service — awaiting 200
        scope = urllib.parse.quote(f"repository:{repo}:pull", safe="")
        token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope={scope}"
        code2_out, _ = remote.run_with_status(
            " ".join([
                "curl -sS",
                f"--connect-timeout {timeout}",
                f"--max-time {timeout}",
                "-o /dev/null",
                r"-w '%{http_code}'",
                f"'{token_url}'",
                "|| echo 000"
            ])
        )
        out2 = (code2_out or "").strip()
        ok2 = (out2 == "200")

        if not ok1:
            fb_out, _ = remote.run_with_status(
                " ".join([
                    "curl -sS",
                    f"--connect-timeout {timeout}",
                    f"--max-time {timeout}",
                    "-o /dev/null",
                    r"-w '%{http_code}'",
                    "https://index.docker.io/v2/",
                    "|| echo 000"
                ])
            )
            ok1 = (fb_out or "").strip() in ("200", "401")

        return bool(ok1 and ok2)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _detect_edition(remote: SSH) -> str:
        """Infer `ce` or `ee` from running/available images; default to `ce`."""
        # 1) running container
        out = remote.run("docker ps --format '{{.Image}}' | head -n1", check=False)
        if "gitlab-ee" in out:
            return "ee"
        if "gitlab-ce" in out:
            return "ce"

        # 2) local images
        imgs = remote.run("docker images --format '{{.Repository}}:{{.Tag}}'", check=False)
        if "gitlab/gitlab-ee" in imgs:
            return "ee"
        if "gitlab/gitlab-ce" in imgs:
            return "ce"

        return "ce"

    def _image_ref(self, remote: SSH, tag: str) -> str:
        edition = self._detect_edition(remote) # still valid with @staticmethod
        return f"gitlab/gitlab-{edition}:{tag}-{edition}.0"

    @staticmethod
    def _already_present(remote: SSH, image: str) -> bool:
        out = remote.run(f"docker image inspect {image} --format '{{{{.Id}}}}'", check=False)
        return bool(out.strip())

    @staticmethod
    def _parse_speed_mb(line: str) -> float | None:
        m = _SPEED_RE.search(line)
        if not m:
            return None
        val = float(m.group(1))
        unit = (m.group(2) or "").lower()
        if unit == "m":      # MB/s
            return val
        if unit == "k":      # kB/s
            return val / 1024.0
        # bytes/s
        return val / (1024.0 * 1024.0)

    # ------------------------------------------------------------------ #
    def pull(self, remote: "SSH", tag: str, edition: str = "ce") -> None:
        image = f"gitlab/gitlab-{edition}:{tag}-{edition}.0"

        _out, rc = remote.run_with_status(f"docker image inspect {image} --format '{{{{.Id}}}}'")
        if rc == 0:
            self.log.info(f"image present locally: {image}")
            return

        backoff = 3
        for attempt in range(1, self.max_retries + 1):
            self.log.info(f"pull attempt {attempt}/{self.max_retries}: {image}")
            t0 = time.monotonic()
            slow = 0
            last_out_ts = time.monotonic()
            last_speed = None

            try:
                for ln in remote.stream(f"docker pull --progress=plain {image}"):
                    now = time.monotonic()

                    if (now - last_out_ts) > self.stall_secs:
                        self.log.warning(f"no output for {self.stall_secs}s — restarting")
                        remote.run(f"pkill -f 'docker pull --progress=plain {image}' || true", check=False)
                        break

                    self.log.debug(ln)
                    last_out_ts = now

                    sp = self._parse_speed_mb(ln)
                    if sp is not None:
                        last_speed = sp
                        slow = slow + 1 if sp < self.min_speed_mb else 0
                        if slow >= self.slow_streak:
                            self.log.warning(f"speed < {self.min_speed_mb} MB/s for {self.slow_streak}s — restarting")
                            remote.run(f"pkill -f 'docker pull --progress=plain {image}' || true", check=False)
                            break
                else:
                    pass
                    dt = time.monotonic() - t0
                    self.log.info(f"pull completed: {image} in {dt:.1f}s (last speed~{(last_speed or 0):.2f} MB/s)")
                    return

            except Exception as e:
                self.log.warning(f"stream failed: {e}")

            # fallback
            _out, rc = remote.run_with_status(f"docker pull {image}")
            if rc == 0:
                self.log.info(f"pull completed: {image}")
                return

            dt = time.monotonic() - t0
            self.log.warning(f"pull interrupted after {dt:.1f}s; retrying in {backoff}s …")
            time.sleep(backoff)
            backoff = min(20, backoff + 3)

        raise RuntimeError(f"Pull {image} failed after {self.max_retries} retries")
