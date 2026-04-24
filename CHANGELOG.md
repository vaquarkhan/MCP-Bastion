# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Fixed

- Dashboard demo metrics respect `BastionConfig` so disabled pillars (for example prompt guard, replay guard) are not faked; synthetic data uses a `demo/...` tool prefix and the default tenant from config.
- `blocked_by_kind` and pillar health: normalize tool-intent and semantic firewall reasons before generic injection matching so "injection-like" argument text is not misclassified.
- Auto-tune latency spike alerts are suppressed until enough samples (warmup) to avoid one-off cold-start noise.
- Cost summary includes `unattributed_usd` when totals are not fully attributed to providers; demo `record_cost` calls use provider dimensions.
- Tests expanded for demo metrics, live traffic helpers, and reason normalization; line coverage for `mcp_bastion` remains at or above 92%.
