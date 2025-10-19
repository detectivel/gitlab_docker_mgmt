# GitLab Docker Upgrader

Automate upgrades of self-hosted **GitLab CE/EE** instances that run in Docker. The upgrader connects to your Docker host over SSH, regenerates (or patches) the `docker-compose.yml`, walks through the officially supported multi-hop upgrade path, and verifies every hop with health checks before moving forward.

---

## ✨ Features at a glance

- **Remote Docker orchestration** – connects over SSH, validates Docker installation, scaffolds Compose files, and creates the required volumes.
- **Upgrade path discovery** – queries GitLab's API to build the mandatory sequence of intermediate versions before downloading any images.
- **Resilient image pulls** – restarts slow or stalled `docker pull` commands and automatically chooses between CE/EE images based on the remote host.
- **Layered health probes** – validates GitLab through `/help`, `/-/metadata`, Docker health, and version checks to ensure readiness.
- **Environment driven** – configuration lives in environment variables or a `.env` file, making the tool CI/CD friendly.
- **Dry-run safety** – preview the complete plan (including detected versions and Compose changes) without modifying anything.

---

## 🧭 How the upgrader works

1. **Connect** to the remote host using the supplied SSH credentials.
2. **Inspect** the current GitLab installation (running containers, Docker volumes, and version files).
3. **Generate or patch** `docker-compose.yml` so it matches the target GitLab release and your configuration.
4. **Download** the required GitLab images, restarting stalled transfers automatically.
5. **Recreate** the stack via Docker Compose.
6. **Probe** GitLab until it is healthy before proceeding to the next hop.

The same workflow also handles first-time installs by detecting that no volumes or containers exist.

---

## ✅ Prerequisites

| Requirement | Notes |
| --- | --- |
| Python 3.9+ | Used for the local CLI. Create a virtual environment for isolation.
| Remote host | Ubuntu or Debian-based VM with SSH access. The script will install Docker/Compose if missing.
| Network access | The remote host needs outbound access to Docker Hub (or a mirror) and the machine running the CLI needs HTTP access to GitLab for metadata discovery.
| Credentials | SSH user with sudo access to Docker directories. GitLab personal access token for metadata endpoints.

---

## 📦 Installation

```bash
# Clone the repository
git clone https://gitlab.example.com/infra/gitlab-docker-upgrader.git
cd gitlab-docker-upgrader

# Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

> The package can also be invoked with `python -m gitlab_docker_upgrader` thanks to the `__main__.py` entry point.

---

## 🔐 Configuration

The upgrader reads configuration from environment variables. A `.env` file is automatically loaded from:

1. `gitlab_docker_upgrader/.env`
2. The repository root `.env`
3. The current working directory

Create a `.env` file with the following baseline variables:

```dotenv
# ─── Remote Ubuntu host (Docker) ────────────────────────────────────────────
GITLAB_NODE_IP=10.0.0.10
GITLAB_NODE_USER=username
GITLAB_NODE_PASSWORD=username_password
GITLAB_COMPOSE_DIR=/home/${GITLAB_NODE_USER}/gitlab
GITLAB_SSL_HOST_DIR=/srv/gitlab/config/ssl

# ─── GitLab image / runtime ─────────────────────────────────────────────────
GITLAB_IMAGE=gitlab/gitlab-ce:latest              # overrides the default bootstrap image
GITLAB_CONTAINER_NAME=gitlab
GITLAB_RESTART_POLICY=unless-stopped

# ─── GitLab HTTP base ────────────────────────────────────────────────────────
GITLAB_HOSTNAME=gitlab.example.com
GITLAB_VERIFY_SSL=false                           # set true when using trusted certs
GITLAB_HTTP_PORT=8080
GITLAB_HTTPS_PORT=9443
GITLAB_HTTPS_ALT_PORT=8443
GITLAB_BASE_URL=https://${GITLAB_HOSTNAME}:${GITLAB_HTTPS_ALT_PORT}       # optional but unlocks richer health probes
GITLAB_PRIVATE_TOKEN=glpat-xxxxxxxxxxxxxxxx

# ─── SSL mount policy ───────────────────────────────────────────────────────
GITLAB_SSL_BIND=true

# ─── Logging (optional) ─────────────────────────────────────────────────────
LOG_LEVEL=INFO
LOG_PATH=/home/${GITLAB_NODE_USER}/gitlab-upgrader.log
LOG_JSON=false
```

Additional toggles include:

| Variable | Purpose | Default |
| --- | --- | --- |
| `GITLAB_SSL_BIND` | `true` uses bind mounts for SSL certs; `false` falls back to a named Docker volume. | `true` |
| `GITLAB_SSL_HOST_DIR` | Explicit host path for SSL material when using bind mounts. | `${GITLAB_COMPOSE_DIR}/gitlab/config/ssl` |
| `LOG_LEVEL`, `LOG_PATH`, `LOG_JSON` | Control optional structured logging when you extend `utils.get_logger`. | `INFO`, `${GITLAB_COMPOSE_DIR}/gitlab-upgrader.log`, `false` |

All variables are defined in [`vars.py`](vars.py) if you need the authoritative list.

---

## ▶️ Usage

Run the CLI from the repository root (with your virtual environment activated):

```bash
python -m gitlab_docker_upgrader <command>
```

Available commands:

| Command | When to use it |
| --- | --- |
| `dry_run` | Prints the detected state, planned upgrade path, and Compose changes without modifying the remote host. |
| `install` | Provision a fresh GitLab instance. Installs Docker if necessary, scaffolds Compose, and deploys the target version. |
| `upgrade` | Perform an in-place upgrade. The upgrader will compute the intermediate versions and apply them sequentially.

During execution you will see live progress logs for SSH commands, Docker pulls, and health checks. Each upgrade hop waits for GitLab to pass the readiness probes before continuing.

### Generate the upgrade ladder

If you only need the intermediate versions (for documentation or a change request), generate `upgrade_path.txt` without performing an upgrade:

```bash
python -m gitlab_docker_upgrader.upgrade_path
```

The file is written to the current working directory and mirrors GitLab's official upgrade path for your detected source version.

---

## 🛠 Remote sudo configuration

The upgrader issues read-only commands such as `ls`, `cat`, `find`, and `test` via `sudo` to inspect Docker volumes. Configure passwordless sudo for these binaries on the remote host (we will use user: ubuntu):

```bash
sudo visudo -f /etc/sudoers.d/gitlab-upgrader
```

```text
ubuntu ALL=(root) NOPASSWD: /usr/bin/ls, /bin/ls, /usr/bin/test, /bin/test, \
    /usr/bin/cat, /bin/cat, /usr/bin/find, /bin/find
```

Adjust the username to match `GITLAB_NODE_USER`, then enforce secure permissions:

```bash
sudo chown root:root /etc/sudoers.d/gitlab-upgrader
sudo chmod 0440 /etc/sudoers.d/gitlab-upgrader
```

Validate as the SSH user:

```bash
sudo -l
sudo -n /usr/bin/ls -la /var/lib/docker/volumes
```

---

## 🚨 Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `docker pull` keeps restarting | Network throughput stays below the watchdog threshold. | Raise `MIN_SPEED_MB` in [`docker_pull.py`](docker_pull.py) or mirror images closer to the host. |
| Compose command missing | Docker Compose plugin is not installed. | Re-run the upgrader with `install` (it will install the plugin) or install manually via Docker documentation. |
| Health probe fails after upgrade | GitLab still booting or wrong external URL. | Check container logs, ensure `GITLAB_HOSTNAME` and port variables match your setup. |
| `.env` file ignored | Not located in a searched path. | Place the file next to `vars.py`, at the repo root, or in the working directory before running the CLI. |

---

## 🤝 Contributing & local development

1. Set up the virtual environment as shown in the installation section.
2. Install development tools if needed (`pip install -r requirements.txt` already includes the runtime deps).
3. Run the test suite:

   ```bash
   pytest
   ```

4. Follow the existing code style (Python 3.13 compatible, linted with Ruff as configured in `pyproject.toml`).

Pull requests should include updates to documentation when user-facing behavior changes.

---

## 📄 License

This project is released under the [MIT License](LICENSE).
