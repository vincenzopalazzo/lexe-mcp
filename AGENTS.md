AGENTS.md — lexe-mcp

Operating manual for humans and coding agents. Read this before touching
the tree or wiring the server into a client.

## What this is

Stdlib-only Go MCP server that exposes a [Lexe](https://github.com/lexe)
Lightning node to AI agents. Dual-era Streamable HTTP:

- **Modern** `2026-07-28` — `server/discover`, `_meta` + `MCP-Protocol-Version`
- **Legacy** `2025-03-26` / `2025-11-25` — `initialize` handshake

Single file: `server.go`. No Node, no extra modules.

Since v2 there is **no lexe-sidecar**: the server contains a direct Lexe
gateway client mirroring `lexe-node-client` from
[lexe-public](https://github.com/lexe-app/lexe-public) (MIT, pinned reading
commit `bcabbd3`): outer TLS pinned to the embedded Lexe root CA
(prod/staging, valid to 2034), `CONNECT run.lexe.app:443` with
`Proxy-Authorization: Bearer <lexe_auth_token>` from the caller's SDK
credentials, inner mTLS presenting the credentials' revocable client
certificate and verifying the node certificate against the credentials'
ephemeral CA (or the Lexe CA). Node commands are JSON REST; amounts are
**sats** (Lexe Decimal `Amount`). The optional L402/AgenticMail hop was
removed in v2; that deployment is journaled in
[local.ai docs/43](https://github.com/vincenzopalazzo/local-ai/blob/main/docs/43-lexe-mcp-l402.md)
— do not treat that as this repo's identity.

Live instance: `https://emailagent.hedwig.sh/mcp`.

## Hard rules

1. **No secrets in git.** `config.json` and `config.env` are gitignored.
   Real Lexe SDK credentials stay on the host.
2. **Stdlib only.** Do not add a `go.mod` dependency.
3. **Do not vendor this tree into local.ai.** That repo journals the L402
   deployment; this repo is the server.
4. Verify live before asserting (`curl /health`, then `server/discover` or
   `initialize`). Training cutoffs lose to the MCP revision cadence.

## Install the server

Needs Go ≥ 1.23 to **build**. Runtime is a static binary.

```bash
git clone git@github.com:vincenzopalazzo/lexe-mcp.git
cd lexe-mcp
cp config.example.json config.json   # optional; clients can send Bearer per request
go build -o lexe-mcp .
./lexe-mcp
```

Linux amd64:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o lexe-mcp-linux .
```

### systemd (user unit, no sudo)

The unit assumes the binary and config live in `~/lexe-mcp/`.

```bash
mkdir -p ~/lexe-mcp ~/.config/systemd/user
cp lexe-mcp ~/lexe-mcp/lexe-mcp
cp config.json config.env ~/lexe-mcp/ 2>/dev/null || true
cp systemd/user/lexe-mcp.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now lexe-mcp
curl -sS localhost:8010/health
```

`ExecStart` is `%h/lexe-mcp/lexe-mcp`. Env overrides: `EnvironmentFile=-%h/lexe-mcp/config.env`.

Smoke:

```bash
curl -sS localhost:8010/health
curl -sS -X OPTIONS localhost:8010/mcp -o /dev/null -w '%{http_code}\n'   # 204
curl -sS -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}' \
  localhost:8010/mcp
```

## Install it in an MCP client

Transport is **Streamable HTTP**. The MCP endpoint is `POST /mcp`
(not stdio, not SSE).

```
https://emailagent.hedwig.sh/mcp      # public
http://127.0.0.1:8010/mcp             # local
```

### Auth — Lexe identity as Bearer

`/mcp` is unauthenticated for discovery (`server/discover`, `initialize`,
`tools/list`) and `lexe.analyze`. Everything else hits the **caller's own
node** and needs that caller's Lexe SDK credentials (Lexe app → Menu → SDK
clients) as a Bearer token:

```
Authorization: Bearer <lexeClientCredentials>
```

The blob is parsed per request (long-lived proxy token + mTLS certificate
material) so a public host never holds a node key and callers only reach
their own node. `lexeClientCredentials` in config is only a fallback.

### Goose

`~/.config/goose/config.yaml` (or the desktop MCP panel):

```yaml
extensions:
  lexe:
    enabled: true
    type: streamable_http
    name: lexe
    uri: https://emailagent.hedwig.sh/mcp
    timeout: 60
    headers:
      Authorization: Bearer PASTE_YOUR_LEXE_CLIENT_CREDENTIALS
```

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "lexe": {
      "type": "http",
      "url": "https://emailagent.hedwig.sh/mcp",
      "headers": {
        "Authorization": "Bearer PASTE_YOUR_LEXE_CLIENT_CREDENTIALS"
      }
    }
  }
}
```

### Cursor

```json
{
  "mcpServers": {
    "lexe": {
      "url": "https://emailagent.hedwig.sh/mcp",
      "headers": {
        "Authorization": "Bearer PASTE_YOUR_LEXE_CLIENT_CREDENTIALS"
      }
    }
  }
}
```

### MCP Inspector

```bash
npx @modelcontextprotocol/inspector --transport http --url https://emailagent.hedwig.sh/mcp
```

## Tools (all need the caller's identity unless noted)

| Name | Args | Result |
|---|---|---|
| `lexe.create_invoice` | `description?`, `amount_sats?` | BOLT12 offer string |
| `lexe.pay` | `invoice` or `offer`, `amount_sats?`, `note?`, `proof_note?` | `{settled, index, payment}` and, for settled offer pays, `proof` (`lnp1…`) + `proof_url` (`https://lnproof.space/lnp1…`) |
| `lexe.analyze` | `invoice` or `offer` | local decode: amount/kind, no send, no identity needed |
| `lexe.check_payment` | `index` | `{settled, payment}` |
| `lexe.node_health` | — | node info (version, balances, channels) over the gateway |

`lexe.pay` analyzes locally first, refuses on-chain and LNURL, then calls
the node `pay_invoice` / `pay_offer` and polls `payments/id` /
`payments/updated` (250 ms → 4 s backoff, ~150 s cap) until
`completed|failed`. Offer pays generate the `cid` client-side (32 random
bytes) and mint a payer proof after settlement; a proof failure sets
`proof_error` and does not undo the payment. Optional `payMaxSats` /
`LEXE_PAY_MAX_SATS` (0 = no cap). Gateway/node failures and missing
identity are `isError: true` results, not JSON-RPC errors.

Modern `tools/call` must send `Mcp-Name` matching `params.name`. Results are
`resultType: "complete"` + `content[]` + `structuredContent`.

## Layout

| Path | Role |
|---|---|
| `server.go` | the whole server (MCP layer + direct gateway client) |
| `server_test.go` | unit tests (amounts, classification, index format) |
| `gateway_test.go` | hermetic fake-gateway + fake-node TLS integration tests |
| `go.mod` | `module github.com/vincenzopalazzo/lexe-mcp`, Go 1.23, no require |
| `config.example.json` | committed skeleton |
| `config.json` / `config.env` | secrets — never commit |
| `systemd/user/lexe-mcp.service` | user unit, `ExecStart=%h/lexe-mcp/lexe-mcp` |
| `.github/workflows/ci.yml` | `go vet` + test + build + smoke (`/health`, `initialize`, `OPTIONS`, `tools/list`, identity guard on `lexe.pay`) |

## Config

`config.json` (or `CONFIG_PATH`) plus env overrides:

| Key / env | Default | Required |
|---|---|---|
| `lexeNetwork` / `LEXE_NETWORK` | `mainnet` | picks gateway + embedded CA (`testnet3` → staging) |
| `lexeClientCredentials` / `LEXE_CLIENT_CREDENTIALS` | — | fallback only — clients can send `Authorization: Bearer` instead |
| `port` / `PORT` | `8010` | |
| `host` / `HOST` | `0.0.0.0` | |
| `payMaxSats` / `LEXE_PAY_MAX_SATS` | `0` | outbound `lexe.pay` cap; `0` = no cap |
| `invoiceDescription` / `offerTtlSecs` | `Lightning payment` / `3600` | offer defaults |

No credential fatals at boot.

## Coding notes

- Keep dual-era behaviour. Do not drop `initialize` / `ping` for 2025 clients.
- `server/discover` is mandatory for 2026-07-28.
- `ping` on modern → HTTP 404 + `-32601`. On legacy → `{}`.
- Header/body mismatch → `-32020`. Unknown version → `-32022`.
- `OPTIONS /mcp` must be `204` (CORS). Handle it in `handleMCP` **and** `withCORS`.
- JSON-RPC parse errors → `-32700` / HTTP 400. Unknown tool → `-32602`.
- Tool errors that are gateway/node failures are `isError: true` results, not JSON-RPC errors.
- Do not add SSE `subscriptions/listen` unless we advertise `listChanged`.
- Cross-compile on the Mac; github.com may be unreachable from some hosts.
- Gateway client invariants (pinned by `gateway_test.go`): outer TLS trusts
  ONLY the embedded Lexe CA; CONNECT carries `Proxy-Authorization: Bearer`
  from the **caller's** blob; inner TLS presents the caller's client cert
  and chains the node cert to the caller's eph CA or the Lexe CA; node
  amounts are sats strings; never log or echo credential material.

## Don't

- Commit `config.json`, `config.env`, or binaries (`/lexe-mcp`, `/lexe-mcp-linux`).
- Ask for the Lexe SDK credential in chat; hand a one-liner to paste locally.
- Point Goose `auto` at this URL — pin `lexe` / the http transport.
- Add LNURL support by hand-rolling bech32 + LNURL validation in the payment
  path without a dedicated review — resolve to BOLT11 instead (current v2 stance).
