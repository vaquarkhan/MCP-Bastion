# MCP-Bastion Docker

## One-line run

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
