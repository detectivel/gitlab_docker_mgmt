# vars.py – central runtime configuration
# All values are read from environment variables so that CI/CD systems
# (Jenkins credentials binding, GitLab CI, etc.) can inject them securely.

from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv

# ---------- .env loading ----------
script_dir = Path(__file__).parent

env_loaded = False
env_paths = [
    script_dir / '.env',           # Same directory as vars.py
    script_dir.parent / '.env',    # Parent directory
    Path.cwd() / '.env',           # Current working directory
    Path('.env'),                  # Fallback
]
for env_path in env_paths:
    if env_path.exists():
        load_dotenv(env_path)
        env_loaded = True
        print(f"✅ Loaded environment from: {env_path}")
        break
if not env_loaded:
    print("⚠️  No .env file found, using system environment variables only")

def _env_bool(name: str, default: bool = False) -> bool:
    """Convert 0/1, false/true, yes/no to a real bool."""
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "y"}

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

# ---------- GitLab / API ----------
BASE_URL        = os.getenv("GITLAB_BASE_URL", "")           # optional, used by probe if supplied
PRIVATE_TOKEN   = os.getenv("GITLAB_PRIVATE_TOKEN", "")      # optional token
VERIFY_SSL      = _env_bool("GITLAB_VERIFY_SSL", False)

# ---------- Image / runtime defaults ----------
GITLAB_IMAGE           = os.getenv("GITLAB_IMAGE")
GITLAB_CONTAINER_NAME  = os.getenv("GITLAB_CONTAINER_NAME", "gitlab")
GITLAB_HOSTNAME        = os.getenv("GITLAB_HOSTNAME")
GITLAB_HOSTNAME_FROM_ENV = "GITLAB_HOSTNAME" in os.environ
GITLAB_HTTP_PORT       = _env_int("GITLAB_HTTP_PORT", 8080)
GITLAB_HTTPS_PORT      = _env_int("GITLAB_HTTPS_PORT", 9443)
GITLAB_HTTPS_ALT_PORT  = _env_int("GITLAB_HTTPS_ALT_PORT", 8443)
GITLAB_RESTART_POLICY  = os.getenv("GITLAB_RESTART_POLICY", "unless-stopped")

# Use bind-mount for SSL by default (this matches your live compose on Ubuntu)
# If you explicitly want a named volume 'gitlab_ssl', set GITLAB_SSL_BIND=false in .env
GITLAB_SSL_BIND        = _env_bool("GITLAB_SSL_BIND", True)

# ---------- Remote Docker host (Ubuntu VM) ----------
UBUNTU_HOST     = os.getenv("GITLAB_NODE_IP", "")
UBUNTU_USER     = os.getenv("GITLAB_NODE_USER", "ubuntu")
UBUNTU_PASSWORD = os.getenv("GITLAB_NODE_PASSWORD", "")
GITLAB_NODE_KEY_FILE = os.getenv("GITLAB_NODE_KEY_FILE", "")
GITLAB_NODE_KEY_PASSPHRASE = os.getenv("GITLAB_NODE_KEY_PASSPHRASE", "")

# Compose working directory on the remote host
# If GITLAB_COMPOSE_DIR not provided, default to /home/ubuntu
COMPOSE_DIR     = os.getenv("GITLAB_COMPOSE_DIR", f"/home/{UBUNTU_USER or 'ubuntu'}")

GITLAB_SSL_HOST_DIR = os.getenv(
    "GITLAB_SSL_HOST_DIR",
    f"{COMPOSE_DIR.rstrip('/')}/gitlab/config/ssl"
)
ALLOWED_SUBNET = os.getenv("ALLOWED_SUBNET", "192.168.0.0/16")

# ---------- Logging (optional; consumed by utils.get_logger if you add it) ----------
LOG_LEVEL       = os.getenv("LOG_LEVEL", "INFO")             # DEBUG/INFO/WARN/ERROR
LOG_PATH        = os.getenv("LOG_PATH", f"{COMPOSE_DIR.rstrip('/')}/gitlab-upgrader.log")
LOG_JSON        = _env_bool("LOG_JSON", False)

# ---------- Debug print when executed directly ----------
if __name__ == "__main__":
    print("=== Environment Variables Debug ===")
    print(f"BASE_URL: '{BASE_URL}'")
    print(f"PRIVATE_TOKEN: {'*' * len(PRIVATE_TOKEN) if PRIVATE_TOKEN else '(empty)'}")
    print(f"VERIFY_SSL: {VERIFY_SSL}")
    print(f"GITLAB_IMAGE: '{GITLAB_IMAGE}'")
    print(f"GITLAB_CONTAINER_NAME: '{GITLAB_CONTAINER_NAME}'")
    print(f"GITLAB_HOSTNAME: '{GITLAB_HOSTNAME}'")
    print(f"GITLAB_HOSTNAME_FROM_ENV: {GITLAB_HOSTNAME_FROM_ENV}")
    print(f"GITLAB_HTTP_PORT: {GITLAB_HTTP_PORT}")
    print(f"GITLAB_HTTPS_PORT: {GITLAB_HTTPS_PORT}")
    print(f"GITLAB_HTTPS_ALT_PORT: {GITLAB_HTTPS_ALT_PORT}")
    print(f"GITLAB_RESTART_POLICY: '{GITLAB_RESTART_POLICY}'")
    print(f"GITLAB_SSL_BIND: {GITLAB_SSL_BIND}")
    print(f"GITLAB_SSL_HOST_DIR: '{GITLAB_SSL_HOST_DIR}'")
    print(f"UBUNTU_HOST: '{UBUNTU_HOST}'")
    print(f"UBUNTU_USER: '{UBUNTU_USER}'")
    print(f"UBUNTU_PASSWORD: {'*' * len(UBUNTU_PASSWORD) if UBUNTU_PASSWORD else '(empty)'}")
    print(f"COMPOSE_DIR: '{COMPOSE_DIR}'")
    print(f"LOG_LEVEL: '{LOG_LEVEL}'")
    print(f"LOG_PATH: '{LOG_PATH}'")
    print(f"LOG_JSON: {LOG_JSON}")
    print(f"ALLOWED_SUBNET: {ALLOWED_SUBNET}")

    if BASE_URL and not BASE_URL.startswith(('http://', 'https://')):
        print(f"❌ BASE_URL missing protocol scheme: {BASE_URL}")
        print("   Should start with http:// or https://")
