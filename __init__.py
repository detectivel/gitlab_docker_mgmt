"""gitlab_docker_upgrader – Remote GitLab-in-Docker upgrader."""

from __future__ import annotations

# Re-exports for convenient imports at package level
from .cli import main
from .ssh_client import SSH
from .docker_compose import ComposeScaffolder
from .docker_pull import Puller
from .gitlab_probe import GitLabProbe
from .upgrade_path import write_upgrade_path
from .upgrader import Upgrader
from .ssl_handler import SSLHandler

__all__ = [
    "main",
    "SSH",
    "ComposeScaffolder",
    "Puller",
    "GitLabProbe",
    "write_upgrade_path",
    "Upgrader",
    "SSLHandler",
]

__version__ = "0.2.0"
