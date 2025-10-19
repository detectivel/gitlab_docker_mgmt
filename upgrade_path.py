"""Thin wrapper that re-exports write_upgrade_path from gitlab_projects.py.

Keeps public API intact. Adds a clearer error if the dependency is missing.
"""

from __future__ import annotations

try:
    from .gitlab_projects import write_upgrade_path  # type: ignore
except Exception as e:
    def write_upgrade_path(*args, **kwargs):  # type: ignore
        raise RuntimeError(
            "write_upgrade_path() is unavailable: failed to import from gitlab_projects.py. "
            f"Underlying error: {e}"
        )

__all__ = ["write_upgrade_path"]
