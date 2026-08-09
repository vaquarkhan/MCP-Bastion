# MCP-Bastion Docker

## Prebuilt images (GitHub Container Registry)

**Registry:** `ghcr.io` **·** **Tags:** `latest` is updated on each successful publish from a **`v*`** version tag; image digests and tag history are on each package’s **Versions** page.

**Current release pin:** Dockerfiles use `ARG BASTION_VERSION=5.0.0`, which installs `mcp-bastion-python==5.0.0` inside the proxy image at build time (with PyPI CDN retries). The dashboard image copies `src/` from the repo.

Images are built by [`.github/workflows/publish-docker.yml`](.github/workflows/publish-docker.yml) on each **`v*`** tag (and can be run manually with **Actions → Publish Docker**). For upstream releases:

| Image | Use |
|-------|-----|
| [`ghcr.io/vaquarkhan/mcp-bastion-proxy`](https://github.com/vaquarkhan/MCP-Bastion/pkgs/container/mcp-bastion-proxy) | HTTP MCP entrypoint (see [Dockerfile](Dockerfile))  -  port `8080` |
| [`ghcr.io/vaquarkhan/mcp-bastion-dashboard`](https://github.com/vaquarkhan/MCP-Bastion/pkgs/container/mcp-bastion-dashboard) | Metrics dashboard  -  port `7000` |

**Current release:** **5.0.0** (2026-08-09) - `pip install mcp-bastion-python==5.0.0`

```bash
docker pull ghcr.io/vaquarkhan/mcp-bastion-proxy:v4.0.0
docker run -p 8080:8080 ghcr.io/vaquarkhan/mcp-bastion-proxy:v4.0.0
# :latest tracks the most recent v* tag publish
# docker pull ghcr.io/vaquarkhan/mcp-bastion-proxy:latest
```

**Forks:** replace `vaquarkhan` in the path with your GitHub user or org (lowercase). If a package is private, sign in: `echo "$GITHUB_TOKEN" | docker login ghcr.io -u USER --password-stdin` (use a personal access token with `read:packages`).

## One-line run (local build)

```bash
docker build -t mcp-bastion/proxy .
docker run -p 8080:8080 mcp-bastion/proxy
```

MCP endpoint: http://localhost:8080/mcp

## Docker Compose

```bash
# Proxy only
docker-compose up -d

# With dashboard
docker-compose --profile with-dashboard up -d
# Dashboard: http://localhost:7000
```

## Sidecar pattern

Run Bastion next to your MCP app; your app connects to Bastion at `http://bastion:8080/mcp`:

```bash
docker-compose --profile sidecar up -d
```

Environment variables (optional): `ENABLE_PII`, `ENABLE_RATE_LIMIT`.
