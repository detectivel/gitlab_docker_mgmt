# tests/test_compose_scaffold.py

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import docker_compose

from docker_compose import ComposeScaffolder


class FakeSSH:
    """
    Mini-mock SSH, работающий поверх локальной временной директории.
    Реализуем только то, что вызывает ComposeScaffolder.scaffold_from_template().
    """

    def __init__(self, root: str):
        self.root = Path(root)

    def _abs(self, remote_path: str) -> Path:
        if remote_path.startswith("/"):
            p = remote_path.lstrip("/")
            return self.root / p
        return self.root / remote_path

    def run(self, cmd: str, check: bool = True) -> str:
        cmd = cmd.strip()
        if cmd.startswith("mkdir -p "):
            d = cmd.split("mkdir -p ", 1)[1].strip().strip("'").strip('"')
            self._abs(d).mkdir(parents=True, exist_ok=True)
            return ""

        if cmd.startswith("test -f "):
            f = cmd.split("test -f ", 1)[1].strip().strip("'").strip('"')
            exists = self._abs(f).exists()
            if check and not exists:
                raise RuntimeError(f"[{cmd}] failed: not found")
            return "" if exists else ""

        if check:
            return ""
        return ""

    def run_with_status(self, cmd: str):
        try:
            out = self.run(cmd, check=True)
            return out, 0
        except Exception:
            return "", 1

    def put_file(self, local_path: str, remote_path: str) -> None:
        dst = self._abs(remote_path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "rb") as src, open(dst, "wb") as out:
            out.write(src.read())


class FakeSSLHandler:
    def __init__(self, cert_path: str | None):
        self.cert_path = cert_path or "/home/ubuntu/gitlab/config/ssl"
        has_cert = bool(cert_path)
        self._cert_file = has_cert and (self.cert_path + "/dummy.crt")
        self._key_file = has_cert and (self.cert_path + "/dummy.key")
        self.using_named_volume = not has_cert


def read_file(base: Path, rel: str) -> str:
    return (base / rel.lstrip("/")).read_text(encoding="utf-8")


def test_scaffold_template_with_bind_mount_ssl():
    with TemporaryDirectory() as tmp:
        r = FakeSSH(tmp)
        compose_dir = "/compose"
        ssl = FakeSSLHandler(cert_path="/home/ubuntu/gitlab/config/ssl")

        sc = ComposeScaffolder(r, compose_dir, ssl_handler=ssl)
        sc.scaffold_from_template(
            image="gitlab/gitlab-ce:18.4.1-ce.0",
            hostname="support.lab.local",
            http_port=8080,
            https_port=9443,
            https_alt_port=8443,
            restart_policy="unless-stopped",
        )

        compose_txt = read_file(Path(tmp), f"{compose_dir}/docker-compose.yml")
        env_txt = read_file(Path(tmp), f"{compose_dir}/.env")

        assert " - /home/ubuntu/gitlab/config/ssl:/etc/gitlab/ssl" in compose_txt
        assert ":/etc/gitlab/ssl:ro" not in compose_txt
        assert "gitlab_ssl:" not in compose_txt.split("volumes:\n")[-1]

        assert "GITLAB_HOSTNAME=support.lab.local" in env_txt
        assert "GITLAB_HTTP_PORT=8080" in env_txt
        assert "GITLAB_HTTPS_PORT=9443" in env_txt
        assert "GITLAB_HTTPS_ALT_PORT=8443" in env_txt
        assert "GITLAB_RESTART_POLICY=unless-stopped" in env_txt

        assert "image: gitlab/gitlab-ce:18.4.1-ce.0" in compose_txt


def test_scaffold_template_with_named_volume_ssl():
    with TemporaryDirectory() as tmp:
        r = FakeSSH(tmp)
        compose_dir = "/compose"
        ssl = FakeSSLHandler(cert_path=None)  # _cert_file = None

        sc = ComposeScaffolder(r, compose_dir, ssl_handler=ssl)
        sc.scaffold_from_template(
            image="gitlab/gitlab-ce:18.4.1-ce.0",
            hostname="support.lab.local",
            http_port=8080,
            https_port=9443,
            https_alt_port=8443,
            restart_policy="unless-stopped",
        )

        compose_txt = read_file(Path(tmp), f"{compose_dir}/docker-compose.yml")

        assert " - gitlab_ssl:/etc/gitlab/ssl" in compose_txt

        assert "volumes:" in compose_txt
        tail = compose_txt.split("volumes:\n")[-1]
        assert "gitlab_ssl:" in tail
        assert "external: true" in tail
        assert "name: gitlab_ssl" in tail


def _fake_ports():
    return {
        "80/tcp": [{"HostPort": "8080"}],
        "443/tcp": [{"HostPort": "9443"}],
        "8443/tcp": [{"HostPort": "8443"}],
    }


def _fake_mounts():
    return [
        {"Destination": "/etc/gitlab"},
        {"Destination": "/var/log/gitlab"},
        {"Destination": "/var/opt/gitlab"},
    ]


def test_scaffold_running_uses_detected_hostname(monkeypatch):
    monkeypatch.setattr(docker_compose, "GITLAB_HOSTNAME_FROM_ENV", False, raising=False)
    monkeypatch.setattr(docker_compose, "GITLAB_HOSTNAME", "support.lab.local", raising=False)

    sc = ComposeScaffolder(FakeSSH("/tmp"), "/compose")
    env_vars = ["GITLAB_OMNIBUS_CONFIG=external_url 'https://gitlab.lab.local:8443'"]
    content = sc._build_compose_content(
        "gitlab/gitlab-ce:18.4.1-ce.0",
        _fake_ports(),
        _fake_mounts(),
        env_vars,
    )

    assert "hostname: gitlab.lab.local" in content
    assert "external_url 'https://gitlab.lab.local:8443'" in content


def test_scaffold_running_honors_hostname_override(monkeypatch):
    monkeypatch.setattr(docker_compose, "GITLAB_HOSTNAME_FROM_ENV", True, raising=False)
    monkeypatch.setattr(docker_compose, "GITLAB_HOSTNAME", "support.lab.local", raising=False)

    sc = ComposeScaffolder(FakeSSH("/tmp"), "/compose")
    env_vars = ["GITLAB_OMNIBUS_CONFIG=external_url 'https://gitlab.lab.local:8443'"]
    content = sc._build_compose_content(
        "gitlab/gitlab-ce:18.4.1-ce.0",
        _fake_ports(),
        _fake_mounts(),
        env_vars,
    )

    assert "hostname: support.lab.local" in content
    assert "external_url 'https://support.lab.local:8443'" in content
