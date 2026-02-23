# MCP-Bastion v2.0 Roadmap

## Honest Assessment

### What's Genuinely Valuable
- **MCP-native security** — No other middleware built specifically for MCP protocol. Fills a real gap as MCP adoption grows.
- **Denial-of-wallet protection** — Rate limiting + iteration caps for agentic AI is underrated. Runaway agents burning API credits is a real problem.
- **Flexible backends** — Local (Presidio + PromptGuard) OR cloud (Bedrock) gives teams options based on privacy/compliance needs.

### What's Less Valuable / Oversold
- **Prompt injection detection** — PromptGuard requires HuggingFace auth (gated model), Bedrock Guardrails costs money. Most teams will skip.
- **Complexity** — For simple MCP servers, this might be overkill. A basic rate limiter + regex PII filter would cover 80% of use cases.

### Real-World Value Proposition

| Use Case | Value |
|----------|-------|
| Enterprise MCP servers with compliance requirements | High |
| Agentic workflows with tool loops | High |
| Simple MCP tools (file read, search) | Low - overkill |
| Hobby projects | Not needed |

**Bottom line:** Valuable for production MCP deployments where security/cost control matters. For prototyping or simple tools, it's overhead.

---

## High-Impact Features (v2.0)

### 1. Audit Logging & Observability
Every tool call logged with: who, what, when, blocked/allowed, why.

```json
{
  "timestamp": "2026-02-22T10:30:00Z",
  "session_id": "abc123",
  "tool": "get_customer_data",
  "action": "BLOCKED",
  "reason": "PII_DETECTED",
  "latency_ms": 45,
  "tokens_used": 150
}
```
- Export to CloudWatch, Datadog, OpenTelemetry
- Compliance teams LOVE this

### 2. Tool-Level Permissions (RBAC)
Define what each agent/user can access.

```python
permissions = {
    "support_agent": ["read_customer", "search_orders"],
    "admin_agent": ["*"],
    "public_agent": ["get_faq", "search_docs"],
}
```
- Block unauthorized tool access before execution
- Essential for multi-tenant MCP servers

### 3. Input/Output Schema Validation
Validate tool inputs match expected schema.

```python
@validate_input({"customer_id": str, "amount": float})
@validate_output({"status": str, "transaction_id": str})
async def process_payment(customer_id, amount):
    ...
```
- Catch malformed requests
- Prevent injection via unexpected fields

### 4. Cost Tracking & Budgets
Real-time cost tracking per session/user.

```python
budget = CostTracker(
    max_cost_per_session=0.50,
    max_cost_per_day=10.00,
    alert_threshold=0.80,
)
```
- Track actual $ spent, not just tokens
- Kill switch when budget exceeded

### 5. Semantic Caching
Cache similar queries to reduce LLM calls.

```python
cache = SemanticCache(similarity_threshold=0.95)
# "What's the weather in NYC?" similar to "NYC weather today?" - Return cached response
```
- Huge cost savings for repetitive queries
- Reduces latency

### 6. Circuit Breaker Pattern
Auto-disable failing tools.

```python
circuit_breaker = CircuitBreaker(
    failure_threshold=5,
    recovery_timeout=60,
)
```

### 7. Content Filtering (Beyond PII)
Block/flag specific content types.

```python
filters = ContentFilter(
    block_code_execution=True,
    block_file_paths=True,
    block_urls=True,
    custom_patterns=[r"password", r"api[_-]?key"],
)
```

### 8. Replay Attack Prevention
Prevent request replay attacks.

```python
replay_guard = ReplayGuard(
    require_nonce=True,
    max_request_age_seconds=30,
)
```

---

## Quick Wins (Prioritized by Effort vs Impact)

| Feature | Effort | Impact |
|---------|--------|--------|
| Audit logging | Low | High |
| Tool-level RBAC | Medium | High |
| Cost tracking | Medium | High |
| Circuit breaker | Low | Medium |
| Content filters | Low | Medium |

---

## MCP-Bastion v2.0 Vision

```
+-----------------------------------------------------------------+
| MCP-BASTION v2.0                                                |
+-----------------------------------------------------------------+
| SECURITY          OBSERVABILITY       COST CONTROL               |
| - Prompt Guard    - Audit Logs       - Token Budgets            |
| - PII Redaction   - OpenTelemetry    - Cost Tracking            |
| - RBAC            - Dashboards       - Semantic Cache            |
| - Input Validation - Alerting        - Circuit Breaker           |
| - Replay Guard    - Request Tracing  - Per-User Limits           |
|                                                                 |
| "The complete security and governance layer for MCP servers"    |
+-----------------------------------------------------------------+
```

---

## Implementation Order (Suggested)

1. **Phase 1 — Quick wins:** Audit logging, Circuit breaker, Content filters
2. **Phase 2 — Security:** RBAC, Input validation, Replay guard
3. **Phase 3 — Cost:** Cost tracking, Semantic caching
