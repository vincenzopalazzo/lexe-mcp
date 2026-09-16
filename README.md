# lexe-mcp

[![ci](https://github.com/vincenzopalazzo/lexe-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/vincenzopalazzo/lexe-mcp/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**Expose a [Lexe](https://github.com/lexe) Lightning node to AI agents over [MCP](https://modelcontextprotocol.io) — with no sidecar, single static binary.**

Stdlib-only Go. Speaks Streamable HTTP in both protocol eras — modern
[`2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
(`server/discover`) and legacy `2025-03-26` / `2025-11-25` (`initialize`) —
so it drops into any current MCP client without adapters.

Since v2 the server talks **directly to the Lexe gateway** exactly like the
official SDK does (mirroring [lexe-public](https://github.com/lexe-app/lexe-public)
`lexe-node-client`, MIT): outer TLS pinned to Lexe's root CA, an HTTPS
`CONNECT` tunnel to `run.lexe.app` authenticated with the long-lived gateway
proxy token from your SDK credentials, and inner mTLS using the revocable
client certificate from the same blob. No local daemon, no Rust toolchain,
no `go.mod` dependencies.

```
MCP client ── Streamable HTTP ──▶ lexe-mcp ── TLS+CONNECT+mTLS ──▶ Lexe gateway ──▶ your node
```

| Tool | What it does |
|---|---|
| `lexe.create_invoice` | Create a reusable BOLT12 offer (min amount in sats) |
| `lexe.pay` | Pay a BOLT11 invoice (`lnbc…`) or BOLT12 offer (`lno1…`). Settled offer pays also return a payer proof + `https://lnproof.space/lnp1…` |
| `lexe.analyze` | Decode an invoice/offer locally without sending |
| `lexe.check_payment` | Look up a payment by index; report settled or not |
| `lexe.node_health` | Your node's info (version, balances, channels) over the gateway |

Hosted instance: [`https://emailagent.hedwig.sh/mcp`](https://emailagent.hedwig.sh/mcp).

## Quick start

Requirements: Go ≥ 1.23 to build, and Lexe SDK client credentials
(Lexe app → Menu → SDK clients → Create).

```bash
git clone git@github.com:vincenzopalazzo/lexe-mcp.git
cd lexe-mcp
cp config.example.json config.json   # optional — clients can send credentials per request
go build -o lexe-mcp .
./lexe-mcp                           # listens on :8010

curl -sS localhost:8010/health
```

No credential fatals at boot: the server starts, serves discovery, and
Lightning tool calls fail with `missing Lexe identity` until one is available.

## Auth — Lexe identity as Bearer

`/mcp` is unauthenticated for discovery (`server/discover`, `initialize`,
`tools/list`) and `lexe.analyze` (local decode). Everything else talks to
**the caller's own node** and needs that caller's SDK credentials:

```
Authorization: Bearer <lexeClientCredentials>
```

The credential blob is parsed per request (proxy token + mTLS certificate
material) and forwarded to the gateway — the host never needs a node key,
and each caller only reaches their own node. Server-side
`lexeClientCredentials` in `config.json` is only a fallback for single-user
deployments.

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

**MCP Inspector:**

```bash
npx @modelcontextprotocol/inspector --transport http --url https://emailagent.hedwig.sh/mcp
```

## Protocol

| Era | How clients talk | What is implemented |
|---|---|---|
| **Modern** `2026-07-28` | `MCP-Protocol-Version` + `Mcp-Method` (+ `Mcp-Name` on `tools/call`), `_meta` on every request | **`server/discover` (mandatory)**, `tools/list`, `tools/call`. `ping` is gone → HTTP `404` / `-32601`. |
| **Legacy** `2025-03-26` / `2025-11-25` | `initialize` handshake | `initialize`, `notifications/initialized` → `202`, `tools/list`, `tools/call`, `ping`. Missing `MCP-Protocol-Version` is treated as `2025-03-26`. |

Header/body mismatches → `400` + `-32020`. Unknown protocol version → `400` +
`-32022` listing supported versions. `OPTIONS /mcp` → `204` (CORS).
`tools/call` results use the 2026-07-28 shape (`resultType: "complete"`,
`content[]`, `structuredContent`).

## Configuration

`config.json` (or `CONFIG_PATH`), every key overridable via env. See
[`config.example.json`](config.example.json).

| Key / env | Default | Purpose |
|---|---|---|
| `lexeNetwork` / `LEXE_NETWORK` | `mainnet` | `mainnet` → `gateway.lexe.app`, `testnet3` → `gateway.staging.lexe.app` |
| `lexeClientCredentials` / `LEXE_CLIENT_CREDENTIALS` | — | fallback identity; clients can send Bearer instead |
| `port` / `PORT`, `host` / `HOST` | `8010`, `0.0.0.0` | listener |
| `payMaxSats` / `LEXE_PAY_MAX_SATS` | `0` | outbound `lexe.pay` cap; `0` = no cap |
| `invoiceDescription`, `offerTtlSecs` | `Lightning payment`, `3600` | offer defaults |

**Never commit `config.json` or `config.env`** — they are gitignored.

## v1 → v2 migration (breaking)

- `lexe-sidecar` is **gone** — delete the `lexe-sidecar.service` systemd unit.
  Nothing listens on `:5393` anymore.
- The optional L402/AgenticMail hop was removed (`agenticmail.*`,
  `upstreamMcpUrl`, `upstreamMcpToken`, `publicUrl`, `amountSats`, `stateDir`
  config keys; `lexe.my_account` tool; `X-PAYMENT` flow). That experiment is
  journaled in [local.ai docs/43](https://github.com/vincenzopalazzo/local-ai/blob/main/docs/43-lexe-mcp-l402.md).
- `lexe.node_health` now returns your node's info (requires identity) instead
  of the sidecar health ping.
- LNURL and Lightning-address strings are recognized by `lexe.analyze` but
  refused by `lexe.pay` — resolve them to a BOLT11 invoice first.
- `lexe.analyze` is a local decode; it no longer requires an identity.

## systemd (user unit, no sudo)

```bash
mkdir -p ~/lexe-mcp ~/.config/systemd/user
cp lexe-mcp ~/lexe-mcp/lexe-mcp
cp config.json config.env ~/lexe-mcp/ 2>/dev/null || true
cp systemd/user/lexe-mcp.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now lexe-mcp
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
