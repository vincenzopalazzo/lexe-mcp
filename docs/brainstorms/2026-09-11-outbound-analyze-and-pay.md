## Clarified Problem Statement

**Goal:** Let an MCP client say “pay this invoice `<lnbc…|lno1…>`” and have lexe-mcp send from the caller’s Lexe node.

**User lock-in (2026-09-12):** L402 is out of scope. The UX is a single tool call with the invoice or offer string — not a 402 auto-payer.

**Inferences:**
- WHO: caller sending `Authorization: Bearer <lexeClientCredentials>` (same as `lexe.create_invoice`).
- WHAT: `lexe.pay` analyzes via sidecar, refuses on-chain, then `pay_invoice` / `pay_offer` / `pay_lnurl`. Settled BOLT12 offer pays also mint a payer proof (`lnp1…`) and `https://lnproof.space/<proof>`. `lexe.analyze` inspects without sending.
- WHY: server was receive-only.
- SCOPE: Lightning only. Dual-era MCP, stdlib-only. Sidecar failures are `isError: true`.
- SUCCESS: `tools/list` has `lexe.pay` + `lexe.analyze`; `lexe.pay` without Bearer → missing identity; amountless needs `amount_sats`; `check_payment` works on the outbound index.

**Constraints:**
- Stdlib only; dual-era; per-request Bearer; no secrets in git.
- `pay_*` blocks until Lightning terminal — client timeout ≥ ~60–180s.
- Amountless payables require `amount_sats`. Encoded amount must match if both are set.

**Non-goals:**
- L402 receive hop changes, auto-pay of other MCP 402s, on-chain, Cash App, LNURL-withdraw.

**Success criteria:**
- `lexe.pay { invoice }` / `{ offer }` sends and returns `{settled, index, payment}`. Settled offer pays return `proof` + `proof_url` on lnproof.space.
- `lexe.analyze` returns amount/kind without sending.
- On-chain kind refused. CI lists the new tools and greps missing-identity on unpaid `lexe.pay`.

## Approaches Considered

### Approach A: Explicit `lexe.analyze` + `lexe.pay` (chosen)
- Sketch: Analyze then specific sidecar pay endpoint. Optional `payMaxSats` (0 = no cap).
- Affected files: `server.go`, `server_test.go`, `AGENTS.md`, `README.md`, `.github/workflows/ci.yml`, `config.example.json`.
- Tradeoffs: Agent stays in control. No silent 402 spender.
- Effort: S

### Approach B: Transparent L402 payer
- Deferred. User does not want this now.

### Approach C: Quote-then-confirm
- Deferred. Extra round-trip vs “just pay this invoice”.

## Recommendation

**Approach A**, implemented. Primary tool is `lexe.pay`. L402 left as-is.

## Open questions

- Whether to cap `payMaxSats` on the public host (default 0 / unlimited).
