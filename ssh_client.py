from __future__ import annotations
from errno import ENOENT

import base64
import posixpath
import paramiko
from .utils import get_logger


class SSH:
    """Thin wrapper around Paramiko for simple run/stream helpers."""

    def __init__(
        self,
        host: str,
        user: str,
        pw: str | None = None,
        *,
        key_filename: str | None = None,
        pkey: paramiko.PKey | None = None,
        allow_agent: bool = True,
        look_for_keys: bool = True,
        port: int = 22,
        timeout: int = 30,
        cmd_timeout: int | None = None,
    ):
        """
        :param timeout: socket timeout in seconds for the initial SSH handshake
        :param cmd_timeout: optional per-command timeout; ``None`` disables it
        """
        self.cli = paramiko.SSHClient()
        self.cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.user = user
        self.cmd_timeout = cmd_timeout
        self.log = get_logger()

        # If password or explicit key provided, don't trawl local agent/known keys,
        # because Paramiko may crash on broken agent keys (public_blob AttributeError).
        auto_keys = look_for_keys
        auto_agent = allow_agent
        if pw or key_filename or pkey:
            auto_keys = False
            auto_agent = False

        connect_kwargs = dict(
            hostname=host,
            port=port,
            username=user,
            timeout=timeout,
            look_for_keys=auto_keys,
            allow_agent=auto_agent,
        )
        if key_filename:
            connect_kwargs["key_filename"] = key_filename
        if pkey is not None:
            connect_kwargs["pkey"] = pkey
        if pw:
            connect_kwargs["password"] = pw

        # First attempt (may fail if agent keys are problematic in Paramiko 4.x on Windows)
        try:
            self.cli.connect(**connect_kwargs)
        except (paramiko.SSHException, AttributeError) as e:
            # Fallback: hard-disable agent & key lookup and try again
            # This specifically works around "AttributeError: public_blob" from agent keys.
            if "public_blob" in str(e) or isinstance(e, AttributeError):
                self.log.info("SSH: retrying without agent/auto-keys due to broken agent key (public_blob).")
                connect_kwargs["allow_agent"] = False
                connect_kwargs["look_for_keys"] = False
                self.cli.connect(**connect_kwargs)
            else:
                raise

    # ------------------------------- exec -------------------------------- #

    def run(self, cmd: str, check: bool = True, trace: bool = True) -> str:
        """Run *cmd* on the remote host. Return stdout (stripped)."""
        stdout, stderr, rc = self.run_full(cmd, trace=trace)
        if check and rc:
            # show compact error context
            err_preview = self._preview(stderr)
            raise RuntimeError(f"[{cmd}] failed (rc={rc}):\n{err_preview}")
        return stdout.strip()

    def run_with_status(self, cmd: str, trace: bool = True) -> tuple[str, int]:
        """Run *cmd* and return (stdout, exit_status). Never raises."""
        stdout, _stderr, rc = self.run_full(cmd, trace=trace)
        return stdout.strip(), rc

    def run_full(self, cmd: str, trace: bool = True) -> tuple[str, str, int]:
        """Run *cmd* and return (stdout, stderr, exit_status) without raising."""
        # Note: Paramiko's exec_command(timeout=...) sets the Channel timeout for I/O operations.
        stdin, out, err = self.cli.exec_command(cmd, timeout=self.cmd_timeout)
        stdout = out.read().decode(errors="replace")
        stderr = err.read().decode(errors="replace")
        rc = out.channel.recv_exit_status()
        # Lightweight console trace (trimmed)
        if trace:
            if rc == 0:
                self.log.debug(f"{cmd} -> rc=0, out='{self._preview(stdout)}'")
            else:
                self.log.debug(f"{cmd} -> rc={rc}, err='{self._preview(stderr)}'")
        return stdout, stderr, rc

    # ------------------------------ transfer ----------------------------- #

    def put_file(self, local_path: str, remote_path: str) -> None:
        """
        Upload a file from local_path to remote_path.
        1) Try SFTP (fast path).
        2) Fallback: base64 stream via shell (handles binary safely).
        """
        remote_path = remote_path.replace("\\", "/")
        remote_dir = posixpath.dirname(remote_path)

        # 1) SFTP fast path
        try:
            sftp = self.cli.open_sftp()
            try:
                if remote_dir and remote_dir != "/":
                    self._mkdir_p_sftp(sftp, remote_dir)
                sftp.put(local_path, remote_path)
                self.log.info(f"Uploaded {local_path} to {remote_path} via SFTP")
                return
            finally:
                sftp.close()
        except Exception as e:
            self.log.warning(f"SFTP upload failed: {e}. Falling back to base64 streaming…")

        # 2) Fallback: base64 (robust for text/binary)
        try:
            if remote_dir and remote_dir != "/":
                self.run(f"mkdir -p '{remote_dir}'")

            with open(local_path, "rb") as f:
                data_b64 = base64.b64encode(f.read()).decode("ascii")

            tmp_remote = self.run("mktemp -p /tmp .upload_XXXXXX", check=True)
            # Decode atomically to a temp file, then move
            # Use 'set -e' to fail hard if any step fails.
            script = f"""set -e
umask 022
base64 -d > '{tmp_remote}' <<'__B64__'
{data_b64}
__B64__
mv -f '{tmp_remote}' '{remote_path}'
"""
            self.run(script)
            self.log.info(f"Uploaded {local_path} to {remote_path} via base64 stream")
        except Exception as e:
            raise RuntimeError(
                f"All upload methods failed for {local_path} -> {remote_path}: {e}"
            ) from e

    @staticmethod
    def _mkdir_p_sftp(sftp: paramiko.SFTPClient, remote_path: str) -> None:
        """Create a directory recursively via SFTP (idempotent)."""
        # Normalize a path
        remote_path = remote_path.rstrip("/") or "/"
        parts = []
        while remote_path not in ("/", ""):
            parts.append(remote_path)
            remote_path = posixpath.dirname(remote_path)

        for path in reversed(parts):
            try:
                sftp.stat(path)
            except (OSError, paramiko.SSHException) as e:
                if getattr(e, "errno", None) in (ENOENT, 2):
                    try:
                        sftp.mkdir(path)
                    except (OSError, paramiko.SSHException):
                        # race: if it exists now — tolerate
                        try:
                            sftp.stat(path)
                        except Exception:
                            raise
                else:
                    raise

    # ----------------------------- streaming ----------------------------- #

    def stream(self, cmd: str):
        """Yield lines of *cmd* stdout as they arrive (no buffering)."""
        _stdin, out, _err = self.cli.exec_command(cmd, timeout=self.cmd_timeout)
        try:
            for line in iter(out.readline, ""):
                yield line.rstrip("\n")
        finally:
            # Drain exit status to avoid "Channel closed" warnings.
            out.channel.recv_exit_status()

    # ----------------------------- housekeeping -------------------------- #

    def close(self):
        self.cli.close()

    @staticmethod
    def _preview(text: str, limit: int = 200) -> str:
        """Return a compact one-line preview for logs."""
        text = text.replace("\n", "\\n")
        return (text[:limit] + "…") if len(text) > limit else text
