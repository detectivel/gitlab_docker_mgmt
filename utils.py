from __future__ import annotations

import json
import logging
import os
import posixpath
import re
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Optional

# --------------------------------------------------------------------
# keep existing API used by docker_compose.py
# --------------------------------------------------------------------
def _replace_tag_sed(compose_file, tag, edition):
    pattern = (
        rf"gitlab/gitlab-{edition}:[0-9]+\.[0-9]+\.[0-9]+-{edition}\.0"
    )
    replacement = f"gitlab/gitlab-{edition}:{tag}-{edition}.0"
    return f"sed -i -E 's|{pattern}|{replacement}|' {compose_file}"


# --------------------------------------------------------------------
# logging helpers (optional to use)
#   get_logger()  -> configured logger
#   log_step/ok/warn/fail/info/debug -> dual: prints + logs (if logger exists)
# --------------------------------------------------------------------

_LOGGER = None  # lazily configured


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)

def _remote_is_dir(remote, path: str) -> bool:
    """Return True if path exists and is a directory on the remote host."""
    if not path:
        return False
    out = remote.run(f"[ -d '{path}' ] && echo OK || true", check=False).strip()
    if out == "OK":
        return True
    out = remote.run(f"sudo [ -d '{path}' ] && echo OK || true", check=False).strip()
    return out == "OK"

def docker_root_dir(remote) -> str:
    """
    Discover Docker root directory on the remote host without hardcoding usernames.

    Priority:
      1) Explicit override: DOCKER_ROOT_DIR (env on the remote)
      2) docker info --format '{{.DockerRootDir}}' (then sudo docker info)
      3) Well-known system locations (/var/lib/docker, snap)
      4) Rootless candidate derived from env-driven compose dir (GITLAB_COMPOSE_DIR)
         e.g. /home/${GITLAB_NODE_USER}/.local/share/docker

    Returns an absolute path. Falls back to '/var/lib/docker' if nothing matches.
    """
    # 1) Remote env override
    try:
        override = remote.run("printf %s \"${DOCKER_ROOT_DIR:-}\"", check=False).strip()
        if override and _remote_is_dir(remote, override):
            return override
    except Exception:
        pass

    # 2) Ask Docker directly
    for cmd in (
        "docker info --format '{{json .DockerRootDir}}'",
        "sudo docker info --format '{{json .DockerRootDir}}'",
    ):
        try:
            raw = remote.run(cmd, check=False).strip()
            if raw and raw != "null":
                try:
                    # docker prints JSON string if using {{json ...}}
                    import json as _json
                    path = _json.loads(raw)
                except Exception:
                    path = raw.strip().strip('"')
                if isinstance(path, str) and _remote_is_dir(remote, path):
                    return path
        except Exception:
            pass

    # 3) System-wide common locations
    candidates: list[str] = [
        "/var/lib/docker",
        "/var/snap/docker/common/var-lib-docker",
    ]

    # 4) Rootless candidate derived from env (no hardcoded usernames)
    # Prefer GITLAB_COMPOSE_DIR if provided (from your .env),
    # else derive from GITLAB_NODE_USER if available.
    try:
        # Pull values from process env first
        compose_dir = os.getenv("GITLAB_COMPOSE_DIR", "")
        node_user = os.getenv("GITLAB_NODE_USER", "")

        # Try importing your vars.py for CI-injected values (optional)
        try:
            from . import vars as _vars  # type: ignore
            compose_dir = getattr(_vars, "GITLAB_COMPOSE_DIR", compose_dir) or compose_dir
            node_user = getattr(_vars, "GITLAB_NODE_USER", node_user) or node_user
        except Exception:
            pass

        if compose_dir:
            # normalize like /home/<user>  -> /home/<user>/.local/share/docker
            # or any other path -> <compose_dir>/.local/share/docker
            rootless = posixpath.join(compose_dir.rstrip("/"), ".local/share/docker")
            candidates.append(rootless)
        elif node_user:
            candidates.append(f"/home/{node_user}/.local/share/docker")
        else:
            # As a very last resort (no env at all), try expanding remote ~:
            home = remote.run("eval echo ~", check=False).strip()
            if home:
                candidates.append(f"{home.rstrip('/')}/.local/share/docker")
    except Exception:
        pass

    for p in candidates:
        if _remote_is_dir(remote, p):
            return p

    # ultimate fallback
    return "/var/lib/docker"


def docker_volumes_dir(remote) -> str:
    """Return the remote Docker volumes directory derived from docker_root_dir()."""
    root = docker_root_dir(remote).rstrip("/")
    return posixpath.join(root, "volumes")


def get_logger(name: str = "gitlab_upgrader") -> logging.Logger:
    """
    Create (once) and return a process-wide logger.
    Reads LOG_LEVEL, LOG_PATH, LOG_JSON from env or vars.py (if available).
    """
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER

    # defaults
    level_name = os.getenv("LOG_LEVEL", "INFO")
    log_path = os.getenv("LOG_PATH", "")
    json_mode = os.getenv("LOG_JSON", "0").lower() in {"1", "true", "yes", "y"}

    # try importing from vars.py (no hard dependency)
    try:
        from . import vars as _vars  # type: ignore
        level_name = getattr(_vars, "LOG_LEVEL", level_name)
        log_path = getattr(_vars, "LOG_PATH", log_path)
        json_mode = getattr(_vars, "LOG_JSON", json_mode)
    except Exception:
        pass

    level = getattr(logging, str(level_name).upper(), logging.INFO)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False  # don't duplicate to root

    # clear old handlers (idempotent)
    for h in list(logger.handlers):
        logger.removeHandler(h)

    # console
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    if json_mode:
        ch.setFormatter(_JsonFormatter())
    else:
        ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(ch)

    # file (optional)
    if log_path:
        try:
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
        except Exception:
            # directory may be '', ignore
            pass
        fh = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=3)
        fh.setLevel(level)
        if json_mode:
            fh.setFormatter(_JsonFormatter())
        else:
            fh.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))
        logger.addHandler(fh)

    _LOGGER = logger
    logger.debug("logger initialized")
    return logger



def _strip_emoji(text: str) -> str:
    """Optionally strip non-ASCII chars (emojis) when LOG_STRIP_EMOJI=1."""
    if os.getenv("LOG_STRIP_EMOJI", "0").lower() not in {"1", "true", "yes", "y"}:
        return text
    try:
        return text.encode("ascii", errors="ignore").decode("ascii", errors="ignore")
    except Exception:
        return text

def route_prints_to_logger(level: str | int | None = None) -> None:
    """Redirect builtins.print to the project logger so legacy prints obey LOG_LEVEL.

    Level precedence:
      - explicit *level* argument, if given
      - env LOG_REDIRECT_LEVEL (e.g., INFO, WARNING)
      - fallback to logger.level
    Toggle with LOG_REDIRECT_PRINT=1 (or call explicitly from code).
    """
    import builtins
    logger = get_logger()
    if isinstance(level, str):
        lvl = getattr(logging, level.upper(), logger.level)
    elif isinstance(level, int):
        lvl = level
    else:
        env_level = os.getenv("LOG_REDIRECT_LEVEL", "")
        lvl = getattr(logging, env_level.upper(), logger.level)

    def _print_to_log(*args, **kwargs):
        sep = kwargs.get("sep", " ")
        end = kwargs.get("end", "\n")
        msg = sep.join(str(a) for a in args) + ("" if end == "" else "")
        msg = _strip_emoji(msg)
        logger.log(lvl, msg)

    builtins.print = _print_to_log

# -------- pretty console helpers (log-only; no unconditional prints) --------

def _emit(kind: str, msg: str):
    """Send message at appropriate level to the configured logger only.
    Former versions printed to console unconditionally which ignored LOG_LEVEL.
    Now console output honors LOG_LEVEL via handler level.
    """
    if _LOGGER is None:
        logger = get_logger()
    else:
        logger = _LOGGER

    if kind == "ok":
        logger.info(msg)
    elif kind == "warn":
        logger.warning(msg)
    elif kind == "fail":
        logger.error(msg)
    elif kind == "debug":
        logger.debug(msg)
    else:
        logger.info(msg)

def log_step(msg: str):  _emit("info", msg)
def log_ok(msg: str):    _emit("ok", msg)
def log_warn(msg: str):  _emit("warn", msg)
def log_fail(msg: str):  _emit("fail", msg)
def log_info(msg: str):  _emit("info", msg)
def log_debug(msg: str): _emit("debug", msg)


# -------- small utility: redact strings in logs --------


def redact(text: str, secrets: list[str] | None = None) -> str:
    """
    Replace occurrences of secrets with '***' for safe logging.
    """
    if not text or not secrets:
        return text
    safe = text
    for s in secrets:
        if s:
            safe = safe.replace(s, "***")
    return safe
