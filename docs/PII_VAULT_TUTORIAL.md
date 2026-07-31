# Tutorial: Reversible PII vault

Keep tool-calling working while ensuring the LLM never sees raw PII.

## Prerequisites

- `mcp-bastion-python` installed
- Optional: Redis when running multiple replicas

## Step 1 - Enable vault (opt-in)

```yaml
# bastion-vault.yaml
audit:
  enabled: false
prompt_guard:
  enabled: false
rate_limit:
  enabled: false
pii:
  enabled: true
pii_vault:
  enabled: true
  ttl_seconds: 3600
  # token_style: low_entropy   # optional: EMAIL_ADDRESS_1 / Person_A
```

Destructive redaction remains the default when `pii_vault.enabled` is omitted or `false`.

## Step 2 - Wrap your server (or run the HTTP proxy)

```python
from mcp_bastion.config import load_config, build_middleware_from_config

mw = build_middleware_from_config(load_config("bastion-vault.yaml"))
# attach mw via compose_middleware / FastMCP as usual
```

Boundary / proxy deployments get the same abstract + hydrate on the wire (JSON and SSE `text/event-stream` event frames).

## Step 3 - Observe abstraction

When a tool returns `"Contact alice@example.com"`, the agent receives something like:

```text
Contact {{pii:EMAIL_ADDRESS:a3f9b2c1d4e5}}
```

With `token_style: low_entropy`:

```text
Contact EMAIL_ADDRESS_1
```

Confirm the raw email is absent from the middleware / proxy result.

## Step 4 - Observe hydration

When the agent calls `send_mail` with `{"to": "{{pii:EMAIL_ADDRESS:a3f9b2c1d4e5}}"}`, Bastion restores `alice@example.com` **before** your tool handler runs (or before the proxy forwards upstream) - so SMTP / calendar APIs receive real addresses.

## Step 5 - Scale with Redis

```yaml
state_backend:
  type: redis
  redis_url: redis://127.0.0.1:6379/0
```

Vault maps share across workers via the same backend as FinOps / replay.

## Step 6 - Verify tests locally

```bash
python -m pytest tests/test_pii_vault.py tests/test_proxy_server_coverage.py -q
```

## Non-goals (this release)

- Does not replace Presidio with GLiNER
- Does not require Ollama / GuardEx
- Does not change default `pii` destructive behavior when vault is off

## Related

- [PII_VAULT.md](PII_VAULT.md)
- Example diagram: `images/mcp-bastion-pii-vault.svg`
