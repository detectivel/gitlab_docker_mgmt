from __future__ import annotations

import sys
import re
import html
import paramiko
import requests
import urllib3
from urllib.parse import urlparse, urlunparse
try:  # package context
    from .ssh_client import SSH  # type: ignore
except Exception:  # module context (no parent)
    from ssh_client import SSH  # type: ignore

try:  # package context
    from .vars import PRIVATE_TOKEN, VERIFY_SSL, BASE_URL, UBUNTU_HOST, UBUNTU_USER, UBUNTU_PASSWORD  # type: ignore
except Exception:  # module context (no parent)
    from vars import PRIVATE_TOKEN, VERIFY_SSL, BASE_URL, UBUNTU_HOST, UBUNTU_USER, UBUNTU_PASSWORD  # type: ignore

# Disable SSL warnings if we're using self-signed certificates
if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_VERSION_RE = re.compile(r"GitLab\s+(\d+\.\d+\.\d+)")
HTTP_OK = 200


def _normalize_base_url(url: str) -> str:
    """Ensure the scheme exists; default to https:// if missing."""
    if not url:
        raise ValueError("BASE_URL is empty")
    if not url.startswith(("http://", "https://")):
        print(f"⚠️  BASE_URL missing scheme, assuming https://: {url}")
        url = f"https://{url}"
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError(f"Invalid BASE_URL format: {url}")
    # strip trailing slash for consistency
    return url.rstrip("/")


def _variants_to_try(base_url: str) -> list[str]:
    """Return the list of base URL variants to try (https first, then http fallback)."""
    parsed = urlparse(base_url)
    variants = [base_url]
    if parsed.scheme == "https":
        # add http fallback with the same host:port
        http_parsed = parsed._replace(scheme="http")
        variants.append(urlunparse(http_parsed))
    return variants


def _try_http_endpoints_one(base_url: str) -> str | None:
    """Try all HTTP endpoints against a single base URL."""
    # 1) /-/metadata (16+)
    try:
        res = requests.get(f"{base_url}/-/metadata", verify=VERIFY_SSL, timeout=10)
        if res.status_code == HTTP_OK:
            v = res.json().get("version")
            if v:
                return v
    except requests.RequestException:
        pass

    # 2) /help page
    try:
        res = requests.get(f"{base_url}/help", verify=VERIFY_SSL, timeout=10)
        if res.status_code == HTTP_OK:
            m = _VERSION_RE.search(html.unescape(res.text))
            if m:
                return m.group(1)
    except requests.RequestException:
        pass

    # 3) /api/v4/version (may 401, but try anyway)
    try:
        headers = {"PRIVATE-TOKEN": PRIVATE_TOKEN} if PRIVATE_TOKEN else {}
        res = requests.get(f"{base_url}/api/v4/version", headers=headers, verify=VERIFY_SSL, timeout=10)
        if res.status_code == HTTP_OK:
            j = res.json()
            return j.get("version") or j.get("version_short")  # be lenient
    except requests.RequestException:
        pass

    return None


def _try_http_endpoints(base_url: str) -> tuple[str | None, str | None]:
    """
    Try HTTPS first, then HTTP fallback. Returns (version, effective_base_url) if found.
    """
    for candidate in _variants_to_try(base_url):
        v = _try_http_endpoints_one(candidate)
        if v:
            return v, candidate
    return None, None

def _decode_text(raw: object) -> str:
    """Return str from bytes/bytearray/str safely."""
    if isinstance(raw, (bytes, bytearray)):
        try:
            return raw.decode("utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            return bytes(raw).decode("utf-8", errors="ignore")
    return str(raw)


def _find_gitlab_container_name(remote: SSH) -> str | None:
    """
    Return the first running container name whose image contains 'gitlab' (case-insensitive),
    or None if not found.
    """
    result = remote.run("docker ps --format '{{.Names}}\t{{.Image}}'", check=False)
    if not result:
        return None
    for line in result.strip().splitlines():
        parts = line.split("\t", 1)
        try:
            name, image = parts[0].strip(), parts[1]
        except IndexError:
            continue
        if "gitlab" in image.lower():
            return name
    return None


def _try_ssh_fallback() -> str | None:
    """Try to get the version via SSH from a running container."""
    if not (UBUNTU_HOST and UBUNTU_USER and UBUNTU_PASSWORD):
        return None

    remote: SSH | None = None
    try:
        remote = SSH(UBUNTU_HOST, UBUNTU_USER, UBUNTU_PASSWORD)
        name = _find_gitlab_container_name(remote)
        if not name:
            return None

        raw = remote.run(
            f"docker exec {name} bash -c 'cat /opt/gitlab/embedded/service/gitlab-rails/VERSION'",
            check=False,
        )
        if not raw:
            return None

        return _decode_text(raw).strip()

    except (OSError, TimeoutError, paramiko.SSHException):
        return None
    finally:
        if remote:
            try:
                remote.close()
            except Exception:  # noqa: BLE001
                print("⚠️  SSH close failed")


def detect_version() -> tuple[str, str | None]:
    """
    Detect GitLab version using multiple fallbacks.
    Returns: (version, effective_base_url or None)
    """
    base = _normalize_base_url(BASE_URL)

    # Try HTTP/HTTPS endpoints
    ver, effective = _try_http_endpoints(base)
    if ver:
        return ver, effective

    print("🔄 HTTP endpoints failed, trying SSH fallback...")

    # SSH fallback (requires running container)
    version = _try_ssh_fallback()
    if version:
        return version, None

    raise RuntimeError("Could not detect GitLab version via HTTP or SSH")


if __name__ == "__main__":
    try:
        version, _ = detect_version()
        print(version)
    except Exception as exc:
        sys.exit(f"❌  Error: {exc}")
