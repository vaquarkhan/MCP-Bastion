# MCP-Bastion proxy: one-line MCP server with security middleware.
# Run: docker build -t mcp-bastion/proxy . && docker run -p 8080:8080 mcp-bastion/proxy

FROM python:3.11-slim

WORKDIR /app

# Install deps (minimal for stdio/HTTP server; add torch/presidio for full features)
RUN pip install --no-cache-dir mcp mcp-bastion-python

# Copy server entrypoint
COPY examples/llm_server.py /app/llm_server.py
COPY src /app/src

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["python", "/app/llm_server.py", "--http", "8080", "--host", "0.0.0.0"]
