# MCP-Bastion proxy: one-line MCP server with security middleware.
# Run: docker build -t mcp-bastion/proxy . && docker run -p 8080:8080 mcp-bastion/proxy

FROM python:3.11-slim

WORKDIR /app

ARG BASTION_VERSION=2.0.0
LABEL org.opencontainers.image.version="${BASTION_VERSION}"

# Install from checkout so tag builds do not race the PyPI publish job.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY examples/llm_server.py /app/llm_server.py

ENV PYTHONUNBUFFERED=1

EXPOSE 8080

# 0.0.0.0 required for Docker port publishing; put auth (edge_auth) or a reverse proxy in front for production.
CMD ["python", "/app/llm_server.py", "--http", "8080", "--host", "0.0.0.0"]
