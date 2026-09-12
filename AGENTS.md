# AGENTS.md — lexe-mcp

Operating manual for humans and coding agents. Read this before touching
the tree or wiring the server into a client.

## What this is

Stdlib-only Go MCP server for a local [lexe-sidecar](https://github.com/lexe)
(`127.0.0.1:5393`). Dual-era Streamable HTTP:

- **Modern** `2026-07-28` — `server/discover`, `_meta` + `MCP-Protocol-Version`
- **Legacy** `2025-03-26` / `2025-11-25` — `initialize` handshake

Single file: `server.go`. No Node, no extra modules. Optional L402 hop in
front of another MCP server is documented in
[local.ai docs/43](https://github.com/vincenzopalazzo/local-ai/blob/main/docs/43-lexe-mcp-l402.md)
— do not treat that as this repo's identity.

Live instance: `https://emailagent.hedwig.sh/mcp`.

## Hard rules

1. **No secrets in git.** `config.json` and `config.env` are gitignored.
   Real Lexe SDK credentials and AgenticMail `mk_` keys stay on the host.
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
cp config.example.json config.json
# set lexeClientCredentials (Lexe app → Menu → SDK clients → Create)
# optional L402 hop: agenticmail.masterKey + upstreamMcpUrl

go build -o lexe-mcp .
./lexe-mcp
```

Linux amd64 (agenticmail VM):

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o lexe-mcp-linux .
install -m 0755 lexe-mcp-linux ~/lexe-mcp/lexe-mcp
```

Sidecar must already be listening on `127.0.0.1:5393`.

### systemd (user unit, no sudo)

Units assume the binary and config live in `~/lexe-mcp/`.

```bash
mkdir -p ~/lexe-mcp ~/.config/systemd/user
cp lexe-mcp ~/lexe-mcp/lexe-mcp          # the binary
cp config.json config.env ~/lexe-mcp/    # if you use them
cp systemd/user/lexe-mcp.service     ~/.config/systemd/user/
cp systemd/user/lexe-sidecar.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now lexe-sidecar lexe-mcp
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
(not stdio, not SSE). Public URL if you do not run a local sidecar:

```
https://emailagent.hedwig.sh/mcp
```

Local:

```
http://127.0.0.1:8010/mcp
```

### Auth — Lexe identity as Bearer

Public `/mcp` is unauthenticated for discovery (`server/discover`,
`initialize`, `tools/list`). **Tool calls that hit Lightning** need a Lexe
identity. Send the SDK client credentials (Lexe app → Menu → SDK clients)
as a Bearer token. That identity is forwarded to the sidecar per request,
so you can expose this host without baking *your* node key into the
server:

```
Authorization: Bearer <lexeClientCredentials>
```

`ak_…` tokens are **not** Lexe ids — they are minted AgenticMail keys
from the optional L402 hop and still proxy upstream.

If the request has no Bearer and the server has no
`lexeClientCredentials` in config, `lexe.create_invoice` /
`lexe.pay` / `lexe.check_payment` fail with `missing Lexe identity`.

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

For a local sidecar, set `uri: http://127.0.0.1:8010/mcp`. Omit `headers`
if the server already has `lexeClientCredentials` in `config.json`.

Goose 1.x also accepts a custom provider-style MCP entry; the field that
matters is `type: streamable_http` + `uri`. Do not use `npx` / `command`.

### Claude Desktop / Claude Code

Claude Desktop → Settings → Connectors (or `claude_desktop_config.json`):

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

Older clients that only speak stdio cannot attach to this server. Use a
Streamable HTTP–capable client (Claude Desktop 2026+, Goose, Cursor).

### Cursor

Cursor Settings → MCP → Add new global MCP server:

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

Inspector protocol-era toggle: this server is dual-era. Prefer `2026-07-28`
(`server/discover`); legacy `initialize` still works.

## Tools (unpaid surface)

These work **without** L402 so a client can discover and pay:

| Name | Args | Result |
|---|---|---|
| `lexe.create_invoice` | `description?`, `amount_sats?` | BOLT12 offer string |
| `lexe.pay` | `invoice` or `offer`, `amount_sats?`, `note?`, `proof_note?` | `{settled, index, payment}` and, for settled offer pays, `proof` (`lnp1…`) + `proof_url` (`https://lnproof.space/lnp1…`) |
| `lexe.analyze` | `invoice` or `offer` | decoded amount/kind, no send |
| `lexe.check_payment` | `index` | `{settled, payment}` |
| `lexe.my_account` | `index` | `{email, bearer_token}` after settlement |
| `lexe.node_health` | — | sidecar health |

`lexe.pay` is the “pay this invoice `<lnbc…|lno1…>`” tool. It analyzes first, refuses on-chain, then calls sidecar `pay_invoice` / `pay_offer` / `pay_lnurl`. Amountless strings need `amount_sats`. Optional `payMaxSats` / `LEXE_PAY_MAX_SATS` (0 = no cap). After a settled BOLT12 offer, it calls `create_payer_proof` and returns the lnproof.space link; a proof failure does not undo the payment (`proof_error` is set). Sidecar failures and missing identity are `isError: true`.

Modern `tools/call` must send `Mcp-Name` matching `params.name`. Results are
`resultType: "complete"` + `content[]` + `structuredContent`.

## Layout

| Path | Role |
|---|---|
| `server.go` | the whole server |
| `go.mod` | `module lexe-mcp`, Go 1.23, no require |
| `config.example.json` | committed skeleton |
| `config.json` / `config.env` | secrets — never commit |
| `systemd/user/lexe-mcp.service` | user unit, `ExecStart=%h/lexe-mcp/lexe-mcp` |
| `systemd/user/lexe-sidecar.service` | sidecar on `:5393` |
| `.github/workflows/ci.yml` | `go vet` + build + `/health` + `initialize` + `OPTIONS` + `tools/list` |

## Config

`config.json` (or `CONFIG_PATH`) plus env overrides:

| Key / env | Default | Required |
|---|---|---|
| `lexeClientCredentials` / `LEXE_CLIENT_CREDENTIALS` | — | fallback only — clients can send `Authorization: Bearer` instead |
| `lexeSidecarUrl` / `LEXE_SIDECAR_URL` | `http://127.0.0.1:5393` | |
| `port` / `PORT` | `8010` | |
| `host` / `HOST` | `0.0.0.0` | |
| `agenticmail.masterKey` / `AGENTICMAIL_MASTER_KEY` | — | L402 hop only |
| `upstreamMcpUrl` / `UPSTREAM_MCP_URL` | `http://127.0.0.1:8014/mcp` | L402 hop |
| `upstreamMcpToken` / `UPSTREAM_MCP_TOKEN` | — | L402 hop — MCP HTTP Bearer that `:8014` expects (not `ak_`) |
| `publicUrl` / `PUBLIC_URL` | — | advertised in 402 `payment_request_url` |
| `amountSats` / `L402_AMOUNT_SATS` | `1` | L402 hop — min sats on the BOLT12 offer |
| `payMaxSats` / `LEXE_PAY_MAX_SATS` | `0` | outbound `lexe.pay` cap; `0` = no cap |
| `stateDir` | `~/.lexe-mcp` | |

Neither credential fatals at boot. Lightning-only public host: leave both
empty and require clients to send their Lexe SDK credentials as Bearer.

## Coding notes

- Keep dual-era behaviour. Do not drop `initialize` / `ping` for 2025 clients.
- `server/discover` is mandatory for 2026-07-28.
- `ping` on modern → HTTP 404 + `-32601`. On legacy → `{}`.
- Header/body mismatch → `-32020`. Unknown version → `-32022`.
- `OPTIONS /mcp` must be `204` (CORS). Handle it in `handleMCP` **and** `withCORS`.
- JSON-RPC parse errors → `-32700` / HTTP 400. Unknown tool → `-32602`.
- Tool errors that are sidecar failures are `isError: true` results, not JSON-RPC errors.
- Do not add SSE `subscriptions/listen` unless we advertise `listChanged`.
- Cross-compile on the Mac; github.com may be unreachable from some hosts.

## Don't

- Commit `config.json`, `config.env`, or binaries (`/lexe-mcp`, `/lexe-mcp-linux`).
- Ask for the Lexe SDK credential in chat; hand a one-liner to paste locally.
- Point Goose `auto` at this URL — pin `lexe` / the http transport.
