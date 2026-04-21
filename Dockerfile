# MCP-Bastion proxy: HTTP MCP server with bundled example entrypoint.
# Build: docker build -t mcp-bastion/proxy .
# Run:  docker run -p 8080:8080 -e BASTION_CONFIG=/app/bastion.yaml -v /path/to/bastion.yaml:/app/bastion.yaml:ro mcp-bastion/proxy
#
# Uses the published wheel (pinned by default). Override at build time:
#   docker build --build-arg BASTION_PY_VERSION=1.0.15 -t mcp-bastion/proxy .

FROM python:3.11-slim

WORKDIR /app

ARG BASTION_PY_VERSION=1.0.15

RUN python -m pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir "mcp-bastion-python==${BASTION_PY_VERSION}" "mcp>=1.0.0"

COPY examples/llm_server.py /app/llm_server.py
COPY bastion.yaml.example /app/bastion.yaml.example

ENV PYTHONUNBUFFERED=1
ENV BASTION_CONFIG=/app/bastion.yaml.example

LABEL org.opencontainers.image.title="MCP-Bastion proxy" \
      org.opencontainers.image.description="MCP HTTP server with MCP-Bastion security middleware"

EXPOSE 8080

CMD ["python", "/app/llm_server.py", "--http", "8080", "--host", "0.0.0.0"]
