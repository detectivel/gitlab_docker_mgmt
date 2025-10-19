from __future__ import annotations

import json
import logging
import os
import posixpath
import re
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler

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

def docker_root_dir(remote) -> str:
    """
    Возвращает актуальный Docker Root Dir (где лежит всё, включая volumes).
    Основа — `docker info --format {{.DockerRootDir}}`. Есть fallback’и.

    Примеры путей:
      - /var/lib/docker
      - /var/snap/docker/common/var-lib-docker      (snap)
      - /home/ubuntu/.local/share/docker            (rootless/user)
    """
    candidates: list[str] = []

    # 1) Прямой запрос у Docker (без sudo)
    out = remote.run("docker info --format '{{.DockerRootDir}}'", check=False).strip()
    if out:
        candidates.append(out)

    # 2) Пробуем через sudo — на случай, если docker доступен только root’у
    if not out:
        out_sudo = remote.run("sudo docker info --format '{{.DockerRootDir}}'", check=False).strip()
        if out_sudo:
            candidates.append(out_sudo)

    # 3) Типичные дефолты как запасной вариант
    candidates += [
        "/var/lib/docker",                                   # пакетная установка
        "/var/snap/docker/common/var-lib-docker",            # snap (Ubuntu)
        f"/home/{getattr(remote, 'user', 'ubuntu')}/.local/share/docker",  # rootless
    ]

    # Возвращаем первый реально существующий каталог
    for p in candidates:
        if not p:
            continue
        # проверяем существование директории (с sudo и без)
        if remote.run(f"test -d '{p}' && echo ok || true", check=False).strip() == "ok":
            return p
        if remote.run(f"sudo test -d '{p}' && echo ok || true", check=False).strip() == "ok":
            return p

    # В самом крайнем случае — классика
    return "/var/lib/docker"


def docker_volumes_dir(remote) -> str:
    """Удобная обёртка: вернёт <root>/volumes с нормализацией слэшей."""
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


# -------- pretty console helpers (also write to logger if created) --------

def _emit(kind: str, msg: str):
    """
    Print pretty to console and also log to get_logger() if already initialized.
    """
    prefix = {
        "step": "▶",
        "ok": "✔",
        "warn": "⚠️",
        "fail": "❌",
        "info": "ℹ️",
        "debug": "🛠️",
    }.get(kind, "•")

    line = f"{prefix} {msg}"
    print(line)

    if _LOGGER is not None:
        if kind == "ok":
            _LOGGER.info(msg)
        elif kind == "warn":
            _LOGGER.warning(msg)
        elif kind == "fail":
            _LOGGER.error(msg)
        elif kind == "debug":
            _LOGGER.debug(msg)
        else:
            _LOGGER.info(msg)


def log_step(msg: str):  _emit("step", msg)
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
