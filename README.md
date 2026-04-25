# Cipher Solana Wallet Audit

![CI](https://github.com/cryptomotifs/cipher-solana-wallet-audit/actions/workflows/test.yml/badge.svg)
[![Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-Cipher%20Solana%20Wallet%20Audit-blue?logo=github)](https://github.com/marketplace/actions/cipher-solana-wallet-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A free GitHub Action that scans your repository for **Solana wallet-security
anti-patterns** during CI — plaintext private keys, seed phrases in comments,
leaked `.env` files, hardcoded RPC URLs with embedded API keys, and more.

Drop-in one-liner, zero config required, fails CI before a compromised key
ever lands on `main`.

---

## Why

Most Solana wallet compromises in 2024–2026 trace back to the same boring
mistakes: a secret key pasted into a JSON file, a seed phrase in a comment,
a `.env` committed because it wasn't in `.gitignore`. This action catches
all of those on every push / PR.

It's the same CI check used by [CIPHER Signal Engine](https://github.com/cryptomotifs/cipher-signal-engine).

## Usage

Create `.github/workflows/wallet-audit.yml` in your repo:

```yaml
name: Wallet Security
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cryptomotifs/cipher-solana-wallet-audit@v1
```

That's it.  The action runs on push and PR, annotates the diff with findings,
and fails the job on any `high` or `critical` severity match.

### Configuration

```yaml
- uses: cryptomotifs/cipher-solana-wallet-audit@v1
  with:
    fail-on: high            # low | medium | high | critical (default: high)
    include: '**/*'          # comma-separated globs (default: all files)
    exclude: 'docs/**,tests/fixtures/**'  # comma-separated globs
```

### Outputs

| Output            | Description                                |
|-------------------|--------------------------------------------|
| `findings-count`  | Total number of findings                   |
| `critical-count`  | Number of critical-severity findings       |

Use them in later steps:

```yaml
- id: audit
  uses: cryptomotifs/cipher-solana-wallet-audit@v1
  with:
    fail-on: critical
- if: steps.audit.outputs.findings-count != '0'
  run: echo "::notice::Wallet audit found ${{ steps.audit.outputs.findings-count }} issue(s)"
```

## Rules

| Rule ID                   | Severity | What it catches                                                    |
|---------------------------|----------|--------------------------------------------------------------------|
| `PLAINTEXT_KEY`                     | critical | Base58 strings 86–90 chars long (likely Solana secret keys)        |
| `JSON_KEYPAIR`                      | critical | `[123, 45, ..., 99]` 64-integer arrays (Solana CLI keypair JSON)   |
| `SEED_IN_COMMENT`                   | critical | 12- or 24-word BIP39-style list in a comment                       |
| `SOLANA_CONFIG_KEYPAIR`             | critical | Tracked files named `id.json` or `*-keypair.json`                  |
| `NONCE_ADVANCE_IN_MULTISIG`         | critical | `AdvanceNonce` near `SetAuthority` / `UpgradeProgram` (≤50 lines) — Drift-hack pattern |
| `ENV_LEAK`                          | high     | `.env` file present in the tree but not covered by any `.gitignore`|
| `LOW_LIQUIDITY_ORACLE_WHITELIST`    | high     | Oracle allow-list add with no preceding liquidity / depth check    |
| `UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE`| high     | One tx bundles 2+ admin instructions (SetAuthority / UpgradeProgram) |
| `MNEMONIC_IN_STRING`                | critical | 12/24-word BIP39 phrase as a string literal assigned to `mnemonic` / `seed` / `wallet*phrase` (added v1.2.0) |
| `ANCHOR_WALLET_LEAK`                | critical | `Anchor.toml [provider].wallet` resolves to a keypair file inside the repo (added v1.2.0) |
| `HEX_PRIVATE_KEY`                   | critical | 64- or 128-char hex literal assigned to a `private_key` / `secret_key` / `wallet_secret` / `signer_key` / `keypair_bytes` identifier (added v1.3.0) |
| `HARDCODED_RPC`                     | medium   | Mainnet RPC URL with an embedded `api-key=` / `token=` query param |

The three `NONCE_ADVANCE_IN_MULTISIG` / `LOW_LIQUIDITY_ORACLE_WHITELIST` /
`UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE` rules were added in **v1.1.0** after
the April 2026 Drift hack ($285M, DPRK-linked). See [the post-mortem
article](https://dev.to/cryptomotifs) for the full attack chain and how
each rule maps back to it.

`MNEMONIC_IN_STRING` and `ANCHOR_WALLET_LEAK` were added in **v1.2.0** to
cover two compromise vectors that the v1.0/1.1 rules were silent on:
seed phrases assigned as ordinary string literals (not just inside
comments), and the canonical Anchor framework misconfiguration where
`Anchor.toml`'s provider wallet path resolves to a keypair committed
inside the repo.

`HEX_PRIVATE_KEY` was added in **v1.3.0** to catch the Ethereum-style
`const PRIVATE_KEY = "0x…64-hex…"` and Solana 128-hex secret-key blob
shapes that `PLAINTEXT_KEY` (which targets base58) misses. Strict
identifier-context match keeps it silent on transaction hashes and SHA-256
digests.

All matches are surfaced as **inline GitHub annotations** so they appear
right on the PR diff — no need to dig through logs.

## Example output

```
::error file=scripts/deploy.ts,line=12,title=PLAINTEXT_KEY (critical)::Likely plaintext Solana private key (base58, ~88 chars)
::error file=.env,line=1,title=ENV_LEAK (high)::.env file is present but not covered by .gitignore

=== Cipher Solana Wallet Audit — Summary ===
  critical: 1
      high: 1
    medium: 0
       low: 0
     total: 2
```

## Development

```bash
git clone https://github.com/cryptomotifs/cipher-solana-wallet-audit.git
cd cipher-solana-wallet-audit
python -m pip install pytest
pytest tests/ -v
```

The scanner itself has **zero runtime dependencies** beyond the Python 3.11
standard library.

## Related

[![MCPize — cipher-x402-mcp](https://img.shields.io/badge/MCPize-cipher--x402--mcp%20%240%20%2F%20%249%20%2F%20%2429%20%2F%20%2499-00d084)](https://mcpize.com/mcp/cipher-x402-mcp)

- **[cipher-starter](https://github.com/cryptomotifs/cipher-starter)** — free MIT Solana solo-dev playbook (150+ pages of research + playbooks).
- **[cipher-solana-bot-toolkit](https://github.com/cryptomotifs/cipher-solana-bot-toolkit)** — free MIT toolkit: flash-loan router, volume bot, arb/MEV predator, memecoin launcher, copy trader.
- **[cipher-x402-mcp](https://github.com/cryptomotifs/cipher-x402-mcp)** — free MIT MCP server exposing 8 Solana + macro tools via x402 USDC payments. Managed hosted plans ($0/$9/$29/$99) on **[MCPize](https://mcpize.com/mcp/cipher-x402-mcp)**.

## License

MIT — see [LICENSE](LICENSE).

Built with care by [cryptomotifs](https://github.com/cryptomotifs).
