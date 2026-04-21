# MCP-Bastion Docker

Images install the published **`mcp-bastion-python`** wheel (default pin `1.0.14`; override with `--build-arg BASTION_PY_VERSION=...`). The proxy image includes `bastion.yaml.example` and sets **`BASTION_CONFIG=/app/bastion.yaml.example`** by default. For production, mount your own file and point `BASTION_CONFIG` at it.

**Image size and build time:** `mcp-bastion-python` declares heavy dependencies (PyTorch, spaCy, Presidio, and related stacks). On Linux `amd64`, `pip` may pull large CUDA-related wheels for PyTorch. Expect a multi-gigabyte image and a long first `docker build` unless you use a private index or a slim dependency variant you maintain yourself.

## One-line run

```bash
docker build -t mcp-bastion/proxy .
docker run -p 8080:8080 mcp-bastion/proxy
```

MCP endpoint: `http://localhost:8080/mcp`

**Production config example:**

```bash
docker run -p 8080:8080 \
  -e BASTION_CONFIG=/app/bastion.yaml \
  -v /path/on/host/bastion.yaml:/app/bastion.yaml:ro \
  mcp-bastion/proxy
```

**Dashboard image:**

```bash
docker build -f Dockerfile.dashboard -t mcp-bastion/dashboard .
docker run -p 7000:7000 mcp-bastion/dashboard
```

## Docker Compose

Use Docker Compose V2 (`docker compose`) or V1 (`docker-compose`) depending on your install.

```bash
# Proxy only
docker compose up -d

# With dashboard
docker compose --profile with-dashboard up -d
```

Dashboard: `http://localhost:7000`. The dashboard image copies the repo `images/` directory so `/images/mcp-bastian.png` resolves when that file exists in the build context.

## Sidecar pattern

Run Bastion next to your MCP app; your app connects to Bastion at `http://bastion:8080/mcp`:

```bash
docker compose --profile sidecar up -d
```

Environment variables (optional): `ENABLE_PII`, `ENABLE_RATE_LIMIT`.
