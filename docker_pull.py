from __future__ import annotations

import re
import time

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
    def pull(self, remote: SSH, tag: str) -> None:
        image = self._image_ref(remote, tag)

        if self._already_present(remote, image):
            self.log.info(f"Image already present: {image} — skipping pull")
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

                    # stall if no output for too long (check BEFORE refreshing the timestamp)
                    if (now - last_out_ts) > self.stall_secs:
                        print(f"\n    ↺ no output for {self.stall_secs}s — restarting")
                        remote.run(f"pkill -f 'docker pull --progress=plain {image}' || true", check=False)
                        break

                    # live console line (truncated)
                    print(f"\r    {ln[:110]:<110}", end="", flush=True)

                    # we got output -> refresh timestamp
                    last_out_ts = now

                    sp = self._parse_speed_mb(ln)
                    if sp is not None:
                        last_speed = sp
                        slow = slow + 1 if sp < self.min_speed_mb else 0
                        if slow >= self.slow_streak:
                            print(f"\n    ↺ speed < {self.min_speed_mb} MB/s for {self.slow_streak}s — restarting")
                            remote.run(f"pkill -f 'docker pull --progress=plain {image}' || true", check=False)
                            break

                    # stall if no output for too long
                    if (time.time() - last_out_ts) > self.stall_secs:
                        print(f"\n    ↺ no output for {self.stall_secs}s — restarting")
                        remote.run(f"pkill -f 'docker pull --progress=plain {image}' || true", check=False)
                        break
                else:
                    # stream finished normally -> success
                    print()  # newline
                    dt = time.monotonic() - t0
                    self.log.info(f"pull completed: {image} in {dt:.1f}s (last speed~{(last_speed or 0):.2f} MB/s)")
                    return

            except Exception as e:
                self.log.warning(f"stream failed: {e}")

            # retry path
            dt = time.monotonic() - t0
            self.log.warning(f"pull interrupted after {dt:.1f}s; retrying in {backoff}s …")
            time.sleep(backoff)
            backoff = min(20, backoff + 3)

        raise RuntimeError(f"Pull {image} failed after {self.max_retries} retries")
