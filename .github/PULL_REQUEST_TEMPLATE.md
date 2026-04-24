## Summary

<!-- What does this change and why? -->

## Checklist

- [ ] `pytest --cov=mcp_bastion --cov-fail-under=92` passes (with `pip install -e ".[dev,policy,dashboard]"`).
- [ ] `npm test` passes at repo root (if you touched JS/TS).
- [ ] `mcp-bastion validate --config bastion.yaml.example` passes (if you touched config loading or the example file).
- [ ] Docs/examples updated if behavior or `bastion.yaml` surface changed.

## Notes for reviewers

<!-- Optional: risk, rollout, follow-ups -->
