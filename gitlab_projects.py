#!/usr/bin/env python3
"""
gitlab_projects.py
------------------
Builds a safe GitLab upgrade “ladder” for Docker:

- The current version comes from detect_version() (see gitlab_version.py).
- The full list of releases is pulled from the official path.json.
- Each step increases the version by no more than +2 MINORs (choosing the max PATCH).
- When moving to a new MAJOR, prefer X.0.* (max patch); otherwise take the earliest
  available MINOR for that MAJOR.

The result (without the current version) is written to upgrade_path.txt.
"""
from __future__ import annotations

from pathlib import Path
from collections import defaultdict
import re
import time
from typing import Any, Iterable

import requests

try:  # package import (when run as gitlab_docker_upgrader.gitlab_projects)
    from .gitlab_version import detect_version  # type: ignore
except Exception:  # standalone import (pytest running from tests/, no package parent)
    from gitlab_version import detect_version  # type: ignore

_URL = "https://gitlab-com.gitlab.io/support/toolbox/upgrade-path/path.json"
_OUT_FILE = "upgrade_path.txt"


# ----------------------------- helpers -----------------------------

def _v(ver: str) -> tuple[int, int, int]:
    """Convert '16.0.10' -> (16, 0, 10) for numeric sorting."""
    a, b, c = ver.split(".")
    return int(a), int(b), int(c)


def _fetch_metadata(retries: int = 3, timeout: float = 15.0) -> dict[str, Any]:
    """Return the full metadata blob from path.json, with retries."""
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(_URL, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict):
                raise ValueError("unexpected payload from path.json")
            return data
        except Exception as e:
            if attempt < retries:
                time.sleep(1.5 * attempt)
            else:
                raise RuntimeError(
                    f"Failed to fetch upgrade path metadata after {retries} attempts: {e}"
                ) from e
    # unreachable
    raise AssertionError("unreachable")


def _all_versions_from_metadata(metadata: dict[str, Any]) -> list[str]:
    """Extract the sorted list of known releases from the metadata."""
    versions = metadata.get("all")
    if not isinstance(versions, Iterable):
        raise ValueError("path.json is missing the 'all' version list")
    cleaned: list[str] = []
    for item in versions:
        if isinstance(item, str):
            cleaned.append(item)
    cleaned.sort(key=_v)
    if not cleaned:
        raise ValueError("empty versions list from path.json")
    return cleaned


_VERSION_PATTERN = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def _normalize_tag(tag: str) -> str | None:
    m = _VERSION_PATTERN.search(tag)
    if not m:
        return None
    v = m.group(1)
    parts = v.split(".")
    if len(parts) == 2:
        maj, minr = map(int, parts)
        return f"{maj}.{minr}"
    if len(parts) == 3:       # X.Y.Z
        maj, minr, patch = map(int, parts)
        return f"{maj}.{minr}.{patch}"
    return None


_FROM_FIELDS = ("from", "from_version", "start", "tag", "current")
_PATH_FIELDS = ("path", "steps", "versions", "targets")


def _sanitize_steps(steps: Iterable[str], current_norm: str) -> list[str]:
    ladder: list[str] = []
    seen = {current_norm}
    for raw in steps:
        if not isinstance(raw, str):
            continue
        normalized = _normalize_tag(raw)
        if not normalized or normalized in seen:
            continue
        ladder.append(normalized)
        seen.add(normalized)
    return ladder


def _scan_for_official_path(node: Any, current_norm: str) -> list[str] | None:
    if isinstance(node, dict):
        # direct key match (e.g. {"16.3.9": [...]})
        for key, val in node.items():
            key_norm = _normalize_tag(key) if isinstance(key, str) else None
            if key_norm == current_norm:
                if isinstance(val, list):
                    return _sanitize_steps(val, current_norm)
                if isinstance(val, dict):
                    for field in _PATH_FIELDS:
                        maybe = val.get(field)
                        if isinstance(maybe, list):
                            return _sanitize_steps(maybe, current_norm)
            # also consider nested dicts/lists
            res = _scan_for_official_path(val, current_norm)
            if res:
                return res

        # field-based match (e.g. {"from": "16.3.9", "path": [...]})
        for from_field in _FROM_FIELDS:
            from_value = node.get(from_field)
            if isinstance(from_value, str) and _normalize_tag(from_value) == current_norm:
                for path_field in _PATH_FIELDS:
                    steps = node.get(path_field)
                    if isinstance(steps, list):
                        return _sanitize_steps(steps, current_norm)

        # fallback to scanning nested values that were not checked above
        for val in node.values():
            res = _scan_for_official_path(val, current_norm)
            if res:
                return res

    elif isinstance(node, list):
        for item in node:
            res = _scan_for_official_path(item, current_norm)
            if res:
                return res

    return None


def _group_by_major_minor(all_versions: list[str]) -> dict[int, dict[int, list[str]]]:
    by_mm: dict[int, dict[int, list[str]]] = {}
    for v in all_versions:
        a, b, c = map(int, v.split("."))
        by_mm.setdefault(a, {}).setdefault(b, []).append(v)

    # сортируем каждый список по патчу
    for maj in by_mm:
        for minr in by_mm[maj]:
            by_mm[maj][minr].sort(key=lambda s: int(s.split(".")[2]))
    return by_mm

def _latest_patch(by_mm: dict[int, dict[int, list[str]]], maj: int, minr: int) -> str | None:
    arr = by_mm.get(maj, {}).get(minr)
    return arr[-1] if arr else None

def _inflate_to_latest_patch(steps: list[str], metadata: dict[str, Any]) -> list[str]:
    if all(isinstance(s, str) and len(s.split(".")) == 3 for s in steps):
        return steps

    versions = metadata.get("all")
    if not isinstance(versions, Iterable):
        return steps

    all_versions = _all_versions_from_metadata(metadata)
    by_mm = _group_by_major_minor(all_versions)
    inflated: list[str] = []
    for s in steps:
        parts = s.split(".")
        if len(parts) == 2:
            maj, minr = map(int, parts)
            latest = _latest_patch(by_mm, maj, minr)
            if latest:
                inflated.append(latest)
        else:
            inflated.append(s)
    return inflated

def _extract_official_path(metadata: dict[str, Any], current: str) -> list[str] | None:
    current_norm = _normalize_tag(current)
    if not current_norm:
        return None
    steps = _scan_for_official_path(metadata, current_norm)
    if steps:
        return _inflate_to_latest_patch(steps, metadata)
    return None


def _first_minor_of_major(by_mm: dict[int, dict[int, list[str]]], maj: int) -> int | None:
    minors = sorted(by_mm.get(maj, {}).keys())
    return minors[0] if minors else None


def _last_minor_of_major(by_mm: dict[int, dict[int, list[str]]], maj: int) -> int | None:
    minors = sorted(by_mm.get(maj, {}).keys())
    return minors[-1] if minors else None


def _next_major(by_mm: dict[int, dict[int, list[str]]], maj: int) -> int | None:
    majors = sorted(by_mm.keys())
    for m in majors:
        if m > maj:
            return m
    return None


# -------------------------- ladder builder --------------------------

def _build_ladder(all_versions: list[str], current: str) -> list[str]:  # noqa: PLR0912
    """
    Build a ladder with “no more than +2 MINOR per step”, always choosing the max patch.
    In the end, ensure the very latest release is included.
    """
    all_versions_sorted = sorted(all_versions, key=_v)
    by_mm = _group_by_major_minor(all_versions_sorted)

    cur_tuple = _v(current)
    if current not in all_versions_sorted:
        not_newer = [v for v in all_versions_sorted if _v(v) <= cur_tuple]
        current = not_newer[-1] if not_newer else all_versions_sorted[0]
        cur_tuple = _v(current)

    latest_overall = all_versions_sorted[-1]
    ladder: list[str] = []

    while _v(current) < _v(latest_overall):
        last_major, last_minor, _ = _v(current)

        minors_in_major = sorted(by_mm.get(last_major, {}).keys())
        if minors_in_major and last_minor < minors_in_major[-1]:
            window_limit = last_minor + 2
            candidate_minor: int | None = None

            for m in minors_in_major:
                if last_minor < m <= window_limit:
                    candidate_minor = m

            if candidate_minor is None:
                for m in minors_in_major:
                    if m > last_minor:
                        candidate_minor = m
                        break

            if candidate_minor is not None:
                target = _latest_patch(by_mm, last_major, candidate_minor)
                if target and _v(target) > _v(current):
                    ladder.append(target)
                    current = target
                    continue

        nm = _next_major(by_mm, last_major)
        if nm is None:
            break

        if 0 in by_mm.get(nm, {}):
            target = _latest_patch(by_mm, nm, 0)
        else:
            fm = _first_minor_of_major(by_mm, nm)
            target = _latest_patch(by_mm, nm, fm) if fm is not None else None

        if not target or _v(target) <= _v(current):
            break

        ladder.append(target)
        current = target

    if _v(latest_overall) > (_v(ladder[-1]) if ladder else _v(current)):
        ladder.append(latest_overall)

    # dedup
    seen: set[str] = set()
    dedup: list[str] = []
    for v in ladder:
        if v not in seen:
            dedup.append(v)
            seen.add(v)
    return dedup


# ----------------------------- public API -----------------------------

def write_upgrade_path(file: Path | str = _OUT_FILE) -> int:
    """Write the ladder (one tag per line) to *file*; return the number of steps."""
    current, _ = detect_version()
    metadata = _fetch_metadata()
    ladder = _extract_official_path(metadata, current)
    if not ladder:
        all_versions = _all_versions_from_metadata(metadata)
        ladder = _build_ladder(all_versions, current)
    Path(file).write_text("\n".join(ladder) + "\n", encoding="utf-8")
    return len(ladder)


if __name__ == "__main__":
    try:
        steps = write_upgrade_path()
        if steps:
            print(f"✔  Saved {steps} upgrade steps to {_OUT_FILE}")
        else:
            print("✔  Your GitLab instance is already up-to-date.")
    except Exception as exc:
        import sys
        sys.exit(f"❌  Error: {exc}")
