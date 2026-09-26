## Summary

## Security impact

- [ ] No security behavior changed.
- [ ] Security behavior changed and relevant `/docs` files were updated.
- [ ] An ADR was added/updated for an architectural decision.

## Source-of-truth checklist

- [ ] I reviewed `docs/security-model.md`.
- [ ] Policy/API behavior matches `docs/policy-spec.md` and `docs/mcp-api.md`.
- [ ] New allow paths have corresponding deny/bypass tests.
- [ ] No secret material is committed.
- [ ] Host-key verification remains fail-closed.
- [ ] No unrestricted normal-role root/shell path was introduced.

## Test plan
