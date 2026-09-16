# Plan: direct-gateway-client (v2.0.0 — remove lexe-sidecar)

Goal: lexe-mcp talks straight to the Lexe gateway (like lexe-cli), single Go binary, no sidecar, no L402.
Protocol ref: lexe-public@bcabbd3 (notes in /tmp/lexe-proto/PROTOCOL_NOTES.md).

## The wire protocol (verified from source)

Credentials blob (what callers send as Bearer) = base64(std, no pad, trim '=') of JSON:
`{user_pk?: hex, client_pk: hex, rev_client_key_der: hex-DER-PKCS8(ed25519),
  rev_client_cert_der: hex-DER, eph_ca_cert_der: hex-DER, lexe_auth_token: b64url-string}`
**No BCS / no signing needed for SDK credentials.** Auth = static token + mTLS:

1. OUTER TLS to `gateway.lexe.app:443` (mainnet) / `gateway.staging.lexe.app:443` (testnet3),
   root CAs = ONLY embedded Lexe CA DER (from lexe-common/data/*.der).
2. `CONNECT run.lexe.app:443` + `Proxy-Authorization: Bearer <lexe_auth_token>` → 200.
3. INNER TLS through tunnel: client presents rev_client_cert(+key); server verified against
   eph_ca_cert_der OR Lexe CA (no hostname check — CA pinning is the boundary).
4. Node commands = JSON REST (mTLS identity, no bearer):
   - GET  /user/v2/node_info → NodeInfo
   - POST /user/v1/create_offer {description?,min_amount?,expiry_secs?} → {offer:"lno1…"}
   - POST /user/v1/pay_invoice {invoice,fallback_amount?,message?,personal_note?} → {created_at}
   - POST /user/v1/pay_offer {cid:hex32,offer,amount,message?,personal_note?} → {created_at}
   - GET  /user/v1/payments/id?id=<ln_…|fs_…> → {maybe_payment:{id,kind,direction,status,…}|null}
   - GET  /user/v1/payments/updated?start_index=u<ms>-<id>&limit= → [BasicPaymentV2…]
   - POST /user/v1/create_payer_proof {index,disclosures,proof_note?} → {proof:"lnp1…"}
Amount = rust-bitcoin Amount serde = float BTC (e.g. 1000 sats → 0.00001).
Status strings: pending|completed|failed. Index = `<19-digit-ms>-<id>`; id `ln_|fs_|ln_…` hex.
Pay polling mirrors wallet: 250ms→4s backoff until completed|failed (cap ~150s).
Offer-pay id is client-generated: cid=32 rand bytes → `fs_<cid>` (we know it up front).
Invoice-pay id unknown client-side → poll payments/updated filtered by created_at==resp+outbound.

## Changes

- `server.go` (single file kept):
  - NEW gateway client: creds parse, outer TLS pin (embedded prod+staging CA), CONNECT+proxy-auth,
    inner mTLS w/ custom chain verify, JSON REST helpers, per-call tunnel (closed in defer), polling.
  - `lexe.analyze` becomes LOCAL decode (prefix classify + BOLT11 hrpart amount). LNURL/ln-address →
    clear "not supported in v2" error on pay. On-chain refused (unchanged).
  - `lexe.node_health` → node_info over tunnel (needs identity). Tool descriptions updated.
  - DELETE: sidecar(), sidecarHealth(), am(), accountForPayment, L402 402/X-PAYMENT flow,
    proxyUpstream, hopHeaders, bearerAk, stateDir store, webhook passthrough, lexe.my_account.
  - Config: remove lexeSidecarUrl/agenticmail.*/upstreamMcp*/publicUrl/amountSats/stateDir;
    add lexeNetwork (mainnet|testnet3) + LEXE_NETWORK. Keep port/host/lexeClientCredentials/payMaxSats.
- `server_test.go`: BOLT11 amount table, classification, creds parse, index round-trip, sats→BTC float,
  **hermetic fake gateway+node TLS integration test** (pins CONNECT auth, mTLS, JSON, polling).
- `config.example.json`, `README.md`, `AGENTS.md`, `CONTRIBUTING.md` (rules unchanged), `.github/workflows/ci.yml`
  (smoke still passes: identity check precedes network), delete `systemd/user/lexe-sidecar.service`.

## Edge cases / risks handled
- Wrong-credential billing: every tunnel keyed to the CALLER's creds (per-request), never server fallback silently.
- No creds in logs/errors ever; bodies truncated 300 chars.
- Timeout budget: pay ≤180s total; polling bounded; tunnel closed via defer (no leaks).
- pay_invoice id discovery races registration → poll with backoff, match created_at+outbound.
- Testnet/mainnet confusion: network sets both gateway URL AND CA pool together.
- Status vocab pinned by test (pending/completed/failed); paymentSettled extended to node vocab.

## Test plan
go vet + go test (new unit + hermetic integration) + go build; CI smoke unchanged must stay green.

Size: L (~+450/−600 LOC). Branch: feat/direct-gateway-client. Release: v2.0.0 after merge.
