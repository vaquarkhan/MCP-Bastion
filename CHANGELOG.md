# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

## [1.0.16] - 2026-04-24

PyPI, npm, and MCP registry publish **1.0.16**; extended pillars (semantic firewall, sensitive classifier, external policy, etc.) and the documentation below are part of this line.

### Documentation

- [PILLARS.md](docs/PILLARS.md) and [README](README.md): aligned pillar counts with code — **18** combined request-path (10 + 8 extended), **14** `pillar_health` dashboard rows (`MetricsStore._build_pillar_health()`), **20+** `bastion.yaml` top-level areas; removed stale “11 / 13” phrasing in the doc index table.

- **README:** **PyPI total downloads** use the live [Shields.io / PePy](https://img.shields.io/pepy/dt/mcp-bastion-python) badge (clicks through to [pepy.tech](https://pepy.tech/projects/mcp-bastion-python)). The old static pepy “total” line badge and the scheduled `update-downloads` workflow / `scripts/update_download_badge.py` were removed; [SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) no longer lists that workflow.

- [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) reframed: free community use with **citation/attribution**, **copyright** and anti–misattribution, and a shorter note on when a **separate commercial** agreement may still apply (governing text remains [LICENSE](LICENSE)). README, `packages/core`, and integration readmes updated for consistency.

### Added

- **Docker on GHCR:** [`.github/workflows/publish-docker.yml`](.github/workflows/publish-docker.yml) builds and pushes `mcp-bastion-proxy` and `mcp-bastion-dashboard` to [GitHub Container Registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry) on every **`v*`** tag (and supports manual **workflow_dispatch** with a custom tag; `latest` is updated only on `v*` tag pushes). [README](README.md) and [DOCKER.md](DOCKER.md) document pull links.

### Fixed

- Dashboard demo metrics respect `BastionConfig` so disabled pillars (for example prompt guard, replay guard) are not faked; synthetic data uses a `demo/...` tool prefix and the default tenant from config.
- `blocked_by_kind` and pillar health: normalize tool-intent and semantic firewall reasons before generic injection matching so "injection-like" argument text is not misclassified.
- Auto-tune latency spike alerts are suppressed until enough samples (warmup) to avoid one-off cold-start noise.
- Cost summary includes `unattributed_usd` when totals are not fully attributed to providers; demo `record_cost` calls use provider dimensions.
- Tests expanded for demo metrics, live traffic helpers, and reason normalization; line coverage for `mcp_bastion` remains at or above 92%.

## Earlier

See [releases](https://github.com/vaquarkhan/MCP-Bastion/releases) and git history for versions before **1.0.16**.
