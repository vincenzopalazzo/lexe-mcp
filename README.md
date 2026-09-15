# lexe-mcp

[![ci](https://github.com/vincenzopalazzo/lexe-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/vincenzopalazzo/lexe-mcp/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**Expose a [Lexe](https://github.com/lexe) Lightning node to AI agents over [MCP](https://modelcontextprotocol.io).**

Stdlib-only Go (zero dependencies, single static binary). Speaks Streamable
HTTP in both protocol eras — modern
[`2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
(`server/discover`) and legacy `2025-03-26` / `2025-11-25` (`initialize`) —
so it drops into any current MCP client without adapters.

Talks to a local [lexe-sidecar](https://github.com/lexe) (`127.0.0.1:5393`):

| Tool | What it does |
|---|---|
| `lexe.create_invoice` | Create a reusable BOLT12 offer (min amount in sats) |
| `lexe.pay` | Pay a BOLT11 invoice (`lnbc…`) or BOLT12 offer (`lno1…`). Settled offer pays also return a payer proof + `https://lnproof.space/lnp1…` |
| `lexe.analyze` | Decode an invoice/offer without sending |
| `lexe.check_payment` | Look up a payment by index; report settled or not |
| `lexe.my_account` | After settlement, return the minted access token |
| `lexe.node_health` | Sidecar / node health |

Hosted instance: [`https://emailagent.hedwig.sh/mcp`](https://emailagent.hedwig.sh/mcp).

```
client ── MCP (Streamable HTTP) ──▶ lexe-mcp (:8010) ──▶ lexe-sidecar (:5393) ──▶ Lexe node
```

## Quick start

Requirements: Go ≥ 1.23 to build, a running lexe-sidecar on `127.0.0.1:5393`,
and Lexe SDK client credentials (Lexe app → Menu → SDK clients → Create).

```bash
git clone git@github.com:vincenzopalazzo/lexe-mcp.git
cd lexe-mcp
cp config.example.json config.json   # fill in lexeClientCredentials
go build -o lexe-mcp .
./lexe-mcp                           # listens on :8010

curl -sS localhost:8010/health
```

The server never fatals on missing credentials — it starts, serves discovery,
and Lightning tool calls fail with `missing Lexe identity` until one is
available. Clients can also send their own credentials per request (below),
so a public host doesn't need a node key baked in.

## Auth — Lexe identity as Bearer

`/mcp` is unauthenticated for discovery (`server/discover`, `initialize`,
`tools/list`). Tool calls that hit Lightning need a Lexe identity:

```
Authorization: Bearer <lexeClientCredentials>
```

That identity is forwarded to the sidecar per request. `ak_…` tokens are
minted AgenticMail keys from the optional L402 hop — not Lexe ids.

## Connect an MCP client

Transport is **Streamable HTTP**, endpoint `POST /mcp` (not stdio, not SSE).

**Goose** — `~/.config/goose/config.yaml` or the desktop MCP panel:

```yaml
extensions:
  lexe:
    enabled: true
    type: streamable_http
    name: lexe
    uri: https://emailagent.hedwig.sh/mcp   # or http://127.0.0.1:8010/mcp
    timeout: 60
    headers:
      Authorization: Bearer PASTE_YOUR_LEXE_CLIENT_CREDENTIALS
```

Omit `headers` if your `config.json` already has `lexeClientCredentials`.

**Claude Desktop / Claude Code** — Settings → Connectors, or
`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "lexe": {
      "type": "http",
      "url": "https://emailagent.hedwig.sh/mcp",
      "headers": { "Authorization": "Bearer PASTE_YOUR_LEXE_CLIENT_CREDENTIALS" }
    }
  }
}
```

**Cursor** — Settings → MCP → Add new global MCP server:

```json
{
  "mcpServers": {
    "lexe": {
      "url": "https://emailagent.hedwig.sh/mcp",
      "headers": { "Authorization": "Bearer PASTE_YOUR_LEXE_CLIENT_CREDENTIALS" }
    }
  }
}
```

Older stdio-only clients cannot attach — use a Streamable HTTP–capable client
(Claude Desktop 2026+, Goose, Cursor).

**MCP Inspector:**

```bash
npx @modelcontextprotocol/inspector --transport http --url https://emailagent.hedwig.sh/mcp
```

## Protocol

| Era | How clients talk | What is implemented |
|---|---|---|
| **Modern** `2026-07-28` | `MCP-Protocol-Version` + `Mcp-Method` (+ `Mcp-Name` on `tools/call`), `_meta` on every request | **`server/discover` (mandatory)**, `tools/list`, `tools/call`. `ping` is gone → HTTP `404` / `-32601`. |
| **Legacy** `2025-03-26` / `2025-11-25` | `initialize` handshake | `initialize`, `notifications/initialized` → `202`, `tools/list`, `tools/call`, `ping`. Missing `MCP-Protocol-Version` is treated as `2025-03-26`. |

Header/body mismatches → `400` + `-32020`. Unknown protocol version → `400`
+ `-32022` listing supported versions. `OPTIONS /mcp` → `204` (CORS).
`tools/call` results use the 2026-07-28 shape (`resultType: "complete"`,
`content[]`, `structuredContent`); `tools/list` includes `ttlMs` / `cacheScope`.

## Optional: L402 gate in front of another MCP server

The same process can sit in front of an upstream MCP endpoint (we run
`agenticmail-mcp` on `:8014`). Unauthenticated non-discovery calls get HTTP
`402` with a **BOLT12 offer** (`lno1…`, Lexe `POST /v2/node/create_offer`).
Pay it, resend `X-PAYMENT: <payment index>`; the hop then proxies with
`upstreamMcpToken`.

BOLT12 is first-class on Lexe (reusable offer, not a single-use BOLT11
invoice) — classic L402 macaroon+BOLT11 is not what this hop speaks. That
deployment is journaled in
[local.ai docs/43](https://github.com/vincenzopalazzo/local-ai/blob/main/docs/43-lexe-mcp-l402.md).

## Configuration

`config.json` (or `CONFIG_PATH`), every key overridable via env. See
[`config.example.json`](config.example.json) for the full skeleton.

| Key / env | Default | Purpose |
|---|---|---|
| `lexeClientCredentials` / `LEXE_CLIENT_CREDENTIALS` | — | fallback identity; clients can send Bearer instead |
| `lexeSidecarUrl` / `LEXE_SIDECAR_URL` | `http://127.0.0.1:5393` | sidecar address |
| `port` / `PORT`, `host` / `HOST` | `8010`, `0.0.0.0` | listener |
| `payMaxSats` / `LEXE_PAY_MAX_SATS` | `0` | outbound `lexe.pay` cap; `0` = no cap |
| `agenticmail.masterKey` / `AGENTICMAIL_MASTER_KEY` | — | L402 hop only |
| `upstreamMcpUrl` / `UPSTREAM_MCP_URL`, `upstreamMcpToken` / `UPSTREAM_MCP_TOKEN` | `:8014/mcp`, — | L402 hop upstream |
| `publicUrl` / `PUBLIC_URL`, `amountSats` / `L402_AMOUNT_SATS` | —, `1` | L402 offer advertising / min sats |
| `stateDir` | `~/.lexe-mcp` | payment→account state |

**Never commit `config.json` or `config.env`** — they are gitignored.

## systemd (user units, no sudo)

```bash
mkdir -p ~/lexe-mcp ~/.config/systemd/user
cp lexe-mcp ~/lexe-mcp/lexe-mcp
cp config.json config.env ~/lexe-mcp/ 2>/dev/null || true
cp systemd/user/lexe-mcp.service     ~/.config/systemd/user/
cp systemd/user/lexe-sidecar.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now lexe-sidecar lexe-mcp
curl -sS localhost:8010/health
```

Cross-compile for a Linux VM from macOS:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o lexe-mcp-linux .
```

## Contributing & security

- [CONTRIBUTING.md](CONTRIBUTING.md) — ground rules (stdlib-only, dual-era protocol behaviour)
- [SECURITY.md](SECURITY.md) — how to report issues, what never to paste in public
- [AGENTS.md](AGENTS.md) — operating manual for coding agents working in this tree

## License

Apache License 2.0 — see [LICENSE](LICENSE).
