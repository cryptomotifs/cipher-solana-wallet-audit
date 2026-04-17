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
| `PLAINTEXT_KEY`           | critical | Base58 strings 86–90 chars long (likely Solana secret keys)        |
| `JSON_KEYPAIR`            | critical | `[123, 45, ..., 99]` 64-integer arrays (Solana CLI keypair JSON)   |
| `SEED_IN_COMMENT`         | critical | 12- or 24-word BIP39-style list in a comment                       |
| `SOLANA_CONFIG_KEYPAIR`   | critical | Tracked files named `id.json` or `*-keypair.json`                  |
| `ENV_LEAK`                | high     | `.env` file present in the tree but not covered by any `.gitignore`|
| `HARDCODED_RPC`           | medium   | Mainnet RPC URL with an embedded `api-key=` / `token=` query param |

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

## License

MIT — see [LICENSE](LICENSE).

Built with care by [cryptomotifs](https://github.com/cryptomotifs).
