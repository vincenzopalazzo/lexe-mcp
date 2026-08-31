# lexe-mcp

**MCP server for [Lexe](https://github.com/lexe) Lightning.**

Stdlib-only Go. Dual-era [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
aligned with [MCP 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/getting-started/intro).

Talks to a local [lexe-sidecar](https://github.com/lexe) (`127.0.0.1:5393`)
and exposes Lightning as MCP tools:

| Tool | What it does |
|---|---|
| `lexe.create_invoice` | Create a reusable BOLT12 offer (min amount in sats) |
| `lexe.check_payment` | Look up a payment by index; report settled or not |
| `lexe.my_account` | After settlement, return the minted access token |
| `lexe.node_health` | Sidecar / node health |

Live instance: [`https://emailagent.hedwig.sh`](https://emailagent.hedwig.sh).

**Auth:** send your Lexe SDK client credentials as
`Authorization: Bearer <credentials>` on `/mcp`. Discovery works without
it; Lightning tool calls use that identity on the sidecar (so the host
does not need a baked-in node key). `ak_…` is an AgenticMail token, not
a Lexe id.

**Install** (binary + Goose / Claude / Cursor): see [AGENTS.md](AGENTS.md).

## Optional: L402 gate in front of another MCP server

The same process can sit in front of an upstream MCP endpoint (we run
`agenticmail-mcp` on `:8014`). Unauthenticated non-discovery calls get
HTTP `402` with a **BOLT12 offer** (`lno1…`, Lexe `POST /v2/node/create_offer`).
Pay it, resend `X-PAYMENT: <payment index>`; the hop then proxies with
`upstreamMcpToken` (the MCP HTTP Bearer that `:8014` requires — not `ak_`).

BOLT12 is first-class on Lexe (reusable offer, not a single-use BOLT11
invoice). Classic L402 macaroon+BOLT11 is **not** what this hop speaks.

That deployment — L402 paywall + AgenticMail bridge — is journaled in
[local.ai docs/43](https://github.com/vincenzopalazzo/local-ai/blob/main/docs/43-lexe-mcp-l402.md),
not this repo's identity.

```
client ── MCP ──▶ lexe-mcp (:8010) ──▶ lexe-sidecar (:5393)
                 └── (optional) L402 ──▶ upstream MCP
```

## Requirements

- Go ≥ 1.23 to **build** (runtime is a single static binary)
- lexe-sidecar on `127.0.0.1:5393`
- Lexe SDK client credentials (app → Menu → SDK clients)

For the optional L402/AgenticMail hop: an AgenticMail `mk_` master key and
an upstream MCP URL.

## Setup

```bash
cp config.example.json config.json
# lexeClientCredentials  (required)
# agenticmail.masterKey / upstreamMcpUrl  (only if using the L402 hop)
```

Optional env overrides: `config.env` (systemd `EnvironmentFile=-`).
Neither file is committed.

## Build

```bash
go build -o lexe-mcp .

# Linux amd64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o lexe-mcp-linux .
```

## Run

```bash
./lexe-mcp

cp systemd/user/lexe-mcp.service     ~/.config/systemd/user/
cp systemd/user/lexe-sidecar.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now lexe-sidecar lexe-mcp
```

`ExecStart` is `%h/lexe-mcp/lexe-mcp`.

## Endpoints

| Route | Behavior |
|---|---|
| `GET /health` | liveness — sidecar up |
| `POST /webhook` | Lexe `payment.finalized` (optional pre-mint) |
| `POST /mcp` | MCP JSON-RPC (Streamable HTTP) |
| `OPTIONS *` | CORS preflight (`204`) |

### Protocol

| Era | How clients talk | What we implement |
|---|---|---|
| **Modern** `2026-07-28` | `MCP-Protocol-Version` + `Mcp-Method` (+ `Mcp-Name` on `tools/call`), `_meta` on every request | **`server/discover` (mandatory)**, `tools/list`, `tools/call`. `ping` is gone → HTTP `404` / `-32601`. |
| **Legacy** `2025-03-26` / `2025-11-25` | `initialize` handshake | `initialize`, `notifications/initialized` → `202`, `tools/list`, `tools/call`, `ping`. Missing `MCP-Protocol-Version` is treated as `2025-03-26`. |

Header/body mismatches → `400` + `-32020`. Unknown protocol version → `400`
+ `-32022` listing `["2026-07-28","2025-11-25","2025-03-26"]`.

`tools/call` results use the 2026-07-28 shape (`resultType: "complete"`,
`content[]`, `structuredContent`). `tools/list` includes `ttlMs` / `cacheScope`.

## State

Idempotent account minting when the L402 hop is enabled. Each payment index
maps to one minted account in `~/.lexe-mcp/payments.json`.
