# Contributing to lexe-mcp

Thanks for helping. This is a deliberately small server — the guardrails
below keep it that way.

## Ground rules

1. **Stdlib only.** Do not add a `go.mod` dependency. No Node, no vendoring,
   no code generation. If a change needs a dependency, it probably belongs
   in a different project.
2. **Keep dual-era behaviour.** Modern `2026-07-28` (`server/discover`,
   `_meta`, `MCP-Protocol-Version`) and legacy `2025-03-26` / `2025-11-25`
   (`initialize`) must both keep working. Do not drop `initialize` / `ping`.
3. **No secrets in git.** `config.json` and `config.env` are gitignored.
   Never paste real Lexe SDK credentials, AgenticMail `mk_` keys, Bearer
   tokens, or `lnp1…` proofs of real payments into issues, PRs, or test
   fixtures. Use placeholder strings.
4. **Protocol error contracts** (covered by tests / CI smoke):
   - `OPTIONS /mcp` → `204`
   - JSON-RPC parse error → `-32700` + HTTP 400
   - header/body mismatch → `-32020`
   - unknown protocol version → `-32022`
   - unknown tool → `-32602`
   - sidecar failures inside a tool → `isError: true` result, not a JSON-RPC error
   - `ping` on modern era → HTTP 404 + `-32601`; on legacy → `{}`
5. **Don't add SSE `subscriptions/listen`** unless we advertise `listChanged`.

## Development

```bash
go vet .
go test .
go build -o lexe-mcp .
```

CI (`.github/workflows/ci.yml`) runs the same plus a live smoke test:
boots the binary, checks `/health`, the `initialize` handshake, CORS
preflight, `tools/list`, and that `lexe.pay` without credentials returns
`isError` with `missing Lexe identity`.

## Commits & PRs

- Small, focused PRs. One behavior per PR.
- Conventional-ish prefixes: `feat:`, `fix:`, `ci:`, `docs:`.
- Include a test when you touch protocol handling, amount resolution, or
  payment/proof logic.
- A PR that needs a local sidecar to demonstrate should include curl
  commands the reviewer can run.
