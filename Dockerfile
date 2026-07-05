# MCP-Bastion proxy: one-line MCP server with security middleware.
# Run: docker build -t mcp-bastion/proxy . && docker run -p 8080:8080 mcp-bastion/proxy

FROM python:3.11-slim

WORKDIR /app

ARG BASTION_VERSION=2.0.1
# Pin to PyPI release (published by tag workflow). Re-dispatch Docker publish after PyPI is green if this step races.
RUN pip install --no-cache-dir mcp "mcp-bastion-python==${BASTION_VERSION}"

LABEL org.opencontainers.image.version="${BASTION_VERSION}"

COPY examples/llm_server.py /app/llm_server.py

ENV PYTHONUNBUFFERED=1

EXPOSE 8080

# 0.0.0.0 required for Docker port publishing; put auth (edge_auth) or a reverse proxy in front for production.
CMD ["python", "/app/llm_server.py", "--http", "8080", "--host", "0.0.0.0"]
