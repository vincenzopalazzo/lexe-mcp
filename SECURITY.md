# Security policy

## Never post publicly

- Real Lexe SDK client credentials (`lexeClientCredentials`)
- AgenticMail master keys (`mk_…`) or minted tokens (`ak_…`)
- Bearer tokens of any kind, `lnp1…` payer proofs of real payments, or
  full invoice strings that identify your node

Use placeholder strings (`PASTE_YOUR_…`) in issues and PRs. Local config
(`config.json`, `config.env`) is gitignored — keep it that way.

## Reporting a vulnerability

Please report privately: open a GitHub
[security advisory](https://github.com/vincenzopalazzo/lexe-mcp/security/advisories/new)
("Report a vulnerability") or email the maintainer. Do not open a public
issue for suspected security problems.

Include: affected endpoint/tool, the request shape (redacted), and the
behavior you observed.

## Scope notes

- The server is designed so a public host does **not** hold a node key:
  clients send their own Lexe identity as `Authorization: Bearer` and it is
  forwarded per request. Deployments that bake `lexeClientCredentials` into
  `config.json` should treat that file as a secret.
- `payMaxSats` / `LEXE_PAY_MAX_SATS` is an outbound payment cap for
  `lexe.pay`; `0` means uncapped. Public hosts should set a cap.
