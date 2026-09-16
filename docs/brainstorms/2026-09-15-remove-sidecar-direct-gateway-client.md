# Brainstorm: Remove lexe-sidecar dependency — direct gateway client in Go

Date: 2026-09-15
Status: clarified, recommendation locked
Input: "the current version is running the lexe sidecar but I would like to remove this dependency and do like lexe-cli"

## Goal

Replace the always-on `lexe-sidecar` process with a direct, pure-Go (stdlib-only) client
that speaks to the Lexe gateway/user node the same way the official Rust SDK does, so
lexe-mcp ships as a single self-contained binary with zero external processes.

## Grounding facts (from `lexe-app/lexe-public`, all MIT-licensed)

- `lexe-cli` uses `LexeWallet::without_db(WalletEnvConfig::mainnet(), credentials)` — no
  local daemon; `lexe-node-client` talks straight to Lexe-hosted infra.
- The wire protocol is **plain HTTPS REST**, not gRPC:
  1. POST `{gateway_url}/user/bearer_auth` — ed25519-signed (`ed25519::Signed<&T>`) BCS
     (`signed_bcs`) `BearerAuthRequestWire` → short-lived bearer token (~10 min, per
     `lexe-node-client/src/client.rs` comments).
  2. HTTPS **CONNECT** tunnel through the gateway proxy to the user node, bearer token as
     proxy auth (re-auth ≈ every 10 min, one reconnect).
  3. REST commands (`create_offer`, `pay_invoice`, `pay_offer`, `pay_lnurl`, `analyze`,
     `get_payment`, `create_payer_proof`, node info) over the tunnel.
- TLS via Lexe's own CA (`lexe_ca::user_gateway_client_config`); `lexe-tls` also contains
  SGX attestation verification (`attest_client`) — requirement TBD.
- Current sidecar (`:5393`) is itself the official `sdk-sidecar` crate wrapping this same
  SDK — we would be inlining a minimal version of what it does.

Go stdlib coverage: HTTPS `net/http` ✅ · CONNECT tunneling `net/http` ✅ · ed25519
`crypto/ed25519` ✅ · custom CA `crypto/tls` ✅ · **BCS encoding: hand-rolled** for a fixed
message set (ULEB128 lengths, deterministic field order — schemas derivable from
`lexe-api-core` models) ⚠️ bounded work, no dependency needed.

## Constraints

- Single self-contained Go binary; **stdlib only** (per CONTRIBUTING.md, published with v0.1.0)
- All MCP tools migrate (payment core + account/health semantics)
- Per-request caller identity (multi-tenant Bearer → per-request `ClientCredentials`)
  must keep working on the hosted instance
- Dual-era MCP behavior (2026-07-28 `server/discover` + legacy `initialize`) unchanged
- Apache-2.0, repo stays single-file-friendly, CI green without any Lexe account

## Non-goals

- The L402/AgenticMail hop — **removed**. User confirmed it has no purpose here; the
  deployment story lives in local.ai docs/43, this repo is the server.
- `lexe.my_account` (AgenticMail mint) — dropped with the L402 hop; no Lexe equivalent.
- General-purpose Go Lexe SDK — implement exactly the calls our 6 tools need, nothing more.
- Channel management, withdrawals, NWC, signup/wallet creation.

## Success criteria

- `go build` produces one binary; no sidecar unit, no lexe CLI, no Rust toolchain
- All tools work against mainnet (and testnet3) with only `ClientCredentials`:
  `create_invoice` (BOLT12 offer), `pay` (BOLT11/BOLT12/LNURL + payer proof), `analyze`,
  `check_payment`, `node_health` → `node-info`
- Callers' Bearer credentials forwarded per request, no shared node state on the host
- CI runs vet/test/build + MCP smoke with a stub transport; no live secrets

## Tool mapping

| MCP tool (v1, sidecar) | v2 direct |
|---|---|
| `lexe.create_invoice` | `CreateOffer` via node tunnel |
| `lexe.pay` | `PayInvoice` / `PayOffer` / `PayLnurl` + `CreatePayerProof` |
| `lexe.analyze` | `Analyze` |
| `lexe.check_payment` | `GetPayment` |
| `lexe.node_health` | `NodeInfo` (auth + reachability) |
| `lexe.my_account` | removed (AgenticMail/L402) |

## Approaches considered

### A. Exec the official `lexe` CLI per tool call
- Go stays stdlib-only; each call runs `lexe pay-invoice --json` with caller credentials.
- Rejected: violates the single-binary constraint (external CLI install for users);
  exec-per-call wallet setup latency; JSON coverage varies per subcommand. Effort S/M.

### B. Pure-Go direct gateway client (chosen)
- Implement bearer_auth (ed25519+BCS), CONNECT tunnel, and the ~8 REST commands in Go
  stdlib inside `server.go` (or one `lexeclient.go`); delete sidecar + L402 code.
- Gains: exactly what was asked — "do like lexe-cli", no daemon, one binary, official
  protocol, per-request identity natural. Costs: we own BCS schemas + auth/token refresh;
  upstream protocol changes require manual sync; payment-critical code. Effort M/L.

### C. Minimal Rust daemon ("sdk-sidecar-lite")
- Purpose-built Rust service exposing our 6 endpoints; lexe-mcp unchanged.
- Rejected: still a second process (the thing being removed) + Rust toolchain; would
  belong in a sibling repo anyway. Effort M/L.

Only B satisfies the single-binary constraint; A and C are recorded for completeness.

## Recommended plan (phased)

1. **Spike** — replicate `node-info` in Go stdlib: embed Lexe CA, bearer_auth with
   ed25519-signed BCS, one REST call. Prove attestation is not a blocker (worst case:
   replicate `attest_client` verification for the fixed gateway cert chain).
2. **Read-only** — `analyze`, `get_payment`; BCS codec for those messages + tests.
3. **Pay path** — `create_offer`, `pay_invoice`/`pay_offer`/`pay_lnurl`, `create_payer_proof`;
   token cache + refresh; per-request credentials.
4. **Cutover** — delete sidecar client + L402/AgenticMail + `my_account`; `node_health` →
   `node-info`; update README/AGENTS/CONTRIBUTING/CI; drop `systemd/user/lexe-sidecar.service`.
5. **Release v2.0.0** (breaking: config keys `lexeSidecarUrl`, `agenticmail.*`, `upstreamMcp*` removed).

## Risks / open questions

- **Attestation**: is SGX quote verification mandatory on the user path? Check
  `lexe_ca::user_gateway_client_config` during the spike — the main spike risk.
- **BCS schemas**: derive per-message from `lexe-api-core` models; version-pin the
  `lexe-public` commit we implement against; integration test vectors from sidecar logs.
- **Protocol stability**: upstream is versioned and public; pin + re-verify per release.
- **Gateway URL**: constant from `WalletEnvConfig::mainnet()/testnet3()` — extract exact host.
- **Token refresh under concurrency**: one refresh goroutine per credential, ~10 min TTL.
