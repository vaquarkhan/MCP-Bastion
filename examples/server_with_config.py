"""
Example: MCP server using policy-as-code (bastion.yaml).

Run from repo root with bastion.yaml (or bastion.yaml.example copied to bastion.yaml):
  PYTHONPATH=src python examples/server_with_config.py

API:
  load_config(path=None)  -> BastionConfig (path from env BASTION_CONFIG or "bastion.yaml")
  build_middleware_from_config(config=None)  -> composed middleware (loads config if None)
"""

import logging
import os
import sys

# Ensure repo root and src on path
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(root, "src"))

logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def main():
    from mcp_bastion import load_config, build_middleware_from_config

    # Load from bastion.yaml (or BASTION_CONFIG env); optional path: load_config("path/to/bastion.yaml")
    config = load_config()
    logger.info(
        "loaded config: prompt_guard=%s pii=%s rate_limit=%s audit=%s",
        config.prompt_guard, config.pii, config.rate_limit, config.audit,
    )
    # Build middleware from config; or one-liner: build_middleware_from_config() to load + build
    middleware = build_middleware_from_config(config)
    logger.info("middleware built from bastion.yaml; wire into your MCP server.")
    return middleware


if __name__ == "__main__":
    main()
