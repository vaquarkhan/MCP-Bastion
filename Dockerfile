# MCP-Bastion proxy: one-line MCP server with security middleware.
# Run: docker build -t mcp-bastion/proxy . && docker run -p 8080:8080 mcp-bastion/proxy

FROM python:3.11-slim

WORKDIR /app

ARG BASTION_VERSION=3.1.2
# Pin to PyPI release. Retry briefly: GHCR builds can race CDN propagation after tag publish.
RUN pip install --no-cache-dir --upgrade pip \
    && for i in 1 2 3 4 5 6 7 8 9 10 11 12; do \
         pip install --no-cache-dir mcp "mcp-bastion-python==${BASTION_VERSION}" && break; \
         echo "PyPI not ready for mcp-bastion-python==${BASTION_VERSION} (attempt $${i}/12); sleeping 20s"; \
         sleep 20; \
       done \
    && python -c "import mcp_bastion; assert mcp_bastion.__version__ == '${BASTION_VERSION}', mcp_bastion.__version__"

LABEL org.opencontainers.image.version="${BASTION_VERSION}"

COPY examples/llm_server.py /app/llm_server.py

ENV PYTHONUNBUFFERED=1

EXPOSE 8080

# 0.0.0.0 required for Docker port publishing; put auth (edge_auth) or a reverse proxy in front for production.
CMD ["python", "/app/llm_server.py", "--http", "8080", "--host", "0.0.0.0"]
