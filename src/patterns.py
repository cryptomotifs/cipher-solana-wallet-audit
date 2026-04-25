"""Regex + heuristic rules for Solana wallet-security audit.

Each rule has:
- id: stable identifier
- severity: low | medium | high | critical
- description: human-readable message
- regex: compiled pattern (optional; some rules are heuristic)
- scope: "content" (scan file contents line-by-line)
       | "path" (match filename itself)
       | "tree" (run a callable over the whole repo)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Rule:
    id: str
    severity: str
    description: str
    regex: re.Pattern | None = None
    scope: str = "content"  # content | path | tree
    # Optional tree-scoped callable returning iter of (file, line, match_text)
    tree_scan: Callable[[Path], Iterable[tuple[Path, int, str]]] | None = None


# ---- BIP39 minimal wordlist sample (first 256 words of official list) ----
# Used as a heuristic to reduce false positives on SEED_IN_COMMENT.
# Full wordlist is 2048 entries; a partial list still cuts false positives
# dramatically while staying fast / vendored-free.
_BIP39_SAMPLE = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
    "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
    "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable",
    "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
    "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable",
    "wallet", "window", "wrap", "wreck", "write", "year", "yellow", "you",
    "young", "youth", "zebra", "zero", "zone", "zoo",
}


# Rule 1: PLAINTEXT_KEY — 86-90 char base58 strings (Solana secret keys are
# 88 base58 chars).  Base58 alphabet excludes 0 O I l.
PLAINTEXT_KEY = Rule(
    id="PLAINTEXT_KEY",
    severity="critical",
    description=(
        "Likely plaintext Solana private key (base58, ~88 chars). "
        "Never commit secret keys. Use env vars, secret managers, or KMS."
    ),
    regex=re.compile(r"[1-9A-HJ-NP-Za-km-z]{86,90}"),
    scope="content",
)


# Rule 2: SEED_IN_COMMENT — BIP39-like 12/24 word list as a comment.
# We scan for any line that is a "#"-ish comment containing 12 or 24
# consecutive lowercase words of reasonable length.
SEED_IN_COMMENT_REGEX = re.compile(
    r"(?://|#|/\*|<!--)\s*((?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})\b"
)

SEED_IN_COMMENT = Rule(
    id="SEED_IN_COMMENT",
    severity="critical",
    description=(
        "Possible BIP39 seed phrase (12/24-word list) in a comment. "
        "Seed phrases give full wallet control and must never be stored in code."
    ),
    regex=SEED_IN_COMMENT_REGEX,
    scope="content",
)


# Rule 3: HARDCODED_RPC — mainnet RPC URL with embedded api-key / token.
HARDCODED_RPC = Rule(
    id="HARDCODED_RPC",
    severity="medium",
    description=(
        "Hardcoded Solana mainnet RPC URL with embedded API key. "
        "Rotate the key and move to an env var."
    ),
    regex=re.compile(
        r"https://[^\s'\"<>]*mainnet[^\s'\"<>]*(?:api[-_ ]?key|token)[=/][^\s'\"<>]+",
        re.IGNORECASE,
    ),
    scope="content",
)


# Rule 4: JSON_KEYPAIR — 64-byte integer array (Solana keypair JSON format).
# Solana CLI writes keys as JSON arrays of 64 integers (0..255).
JSON_KEYPAIR = Rule(
    id="JSON_KEYPAIR",
    severity="critical",
    description=(
        "Solana keypair JSON (64-byte integer array) found in a tracked file. "
        "This is a raw private key; rotate immediately and remove from git history."
    ),
    regex=re.compile(r"\[\s*\d{1,3}(?:\s*,\s*\d{1,3}){63}\s*\]"),
    scope="content",
)


# Rule 5: ENV_LEAK — a `.env` file exists in the repo but is NOT listed in
# any `.gitignore`.  We implement this as a tree-scan callable.
def _scan_env_leak(repo_root: Path) -> Iterable[tuple[Path, int, str]]:
    """Yield (env_file, 1, message) for every .env not covered by .gitignore."""
    env_files: list[Path] = []
    for p in repo_root.rglob(".env*"):
        # Skip example / sample files — conventional safe names.
        if not p.is_file():
            continue
        name = p.name.lower()
        if name.endswith((".example", ".sample", ".template")):
            continue
        # Skip ignore/template directories.
        parts = {part for part in p.parts}
        if "node_modules" in parts or ".git" in parts:
            continue
        env_files.append(p)
    if not env_files:
        return

    # Collect gitignore patterns from every .gitignore in the tree.
    ignore_patterns: list[str] = []
    for gi in repo_root.rglob(".gitignore"):
        try:
            for line in gi.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    ignore_patterns.append(line)
        except OSError:
            continue

    # Crude check: does any pattern look like it would match this .env?
    # Accept ".env", "*.env", ".env*", ".env.*", "/.env", "**/.env"
    def _covers(name: str) -> bool:
        lname = name.lower()
        for pat in ignore_patterns:
            p = pat.lstrip("/").lstrip("!").lower()
            if p in (".env", "*.env", ".env*", ".env.*", "**/.env", ".env/"):
                return True
            # simple glob-ish containment
            if p == lname:
                return True
            if p.startswith(".env"):
                return True
        return False

    for env_path in env_files:
        if not _covers(env_path.name):
            yield (
                env_path,
                1,
                f"{env_path.name} is tracked/present but not covered by any .gitignore.",
            )


ENV_LEAK = Rule(
    id="ENV_LEAK",
    severity="high",
    description=(
        ".env file is present in the repo but not ignored by .gitignore. "
        "Add `.env` to .gitignore before committing any secrets."
    ),
    regex=None,
    scope="tree",
    tree_scan=_scan_env_leak,
)


# Rule 6: SOLANA_CONFIG_KEYPAIR — `~/.config/solana/id.json` or similar path
# signed/tracked in the repo.
SOLANA_CONFIG_KEYPAIR = Rule(
    id="SOLANA_CONFIG_KEYPAIR",
    severity="critical",
    description=(
        "Tracked file matches Solana CLI keypair path (`id.json`, "
        "`*-keypair.json`). Remove from git history and rotate."
    ),
    regex=re.compile(r"(?:^|[\\/])(?:id|[^/\\]+-keypair)\.json$"),
    scope="path",
)


# ---------------------------------------------------------------------------
# Drift-hack (April 2026) derived rules — v1.1.0
# ---------------------------------------------------------------------------
# The $285M Drift exploit combined:
#   (a) durable-nonce pre-signed admin transactions,
#   (b) a fake low-liquidity "CarbonVote Token" added as $100M oracle
#       collateral via an unchecked oracle allow-list path,
#   (c) a bundled transaction containing ComputeBudget + multiple
#       SetAuthority / UpgradeProgram instructions to drain vaults.
# Primary sources:
#   - chainalysis.com/blog/lessons-from-the-drift-hack/
#   - coindesk.com/tech/2026/04/02/how-a-solana-feature-designed-for-
#     convenience-let-an-attacker-drain-usd270-million-from-drift
#   - cyfrin.io/blog/drift-hack-learnings
# These rules are *pattern-based* — a passing scan is not an audit.
# ---------------------------------------------------------------------------

# Which extensions the drift-derived correlation scans cover.
_DRIFT_SCAN_EXTS = {".rs", ".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs", ".py"}

# File-level byte cap for the correlation scans (keeps runtime bounded on
# large Rust crates / bundled JS). 1.5 MiB matches the MAX_FILE_BYTES gate
# used in `audit.py` for content rules.
_DRIFT_MAX_FILE_BYTES = 1_500_000

# Instruction / API names that mean "advance durable nonce".
_NONCE_ADVANCE_TOKENS = (
    "AdvanceNonce",
    "advanceNonce",
    "advance_nonce",
    "nonceAdvance",
    "NonceAdvance",
    "SystemProgram.nonceAdvance",
    "createAdvanceNonceAccountInstruction",
)

# Instruction / API names that change authority / upgrade program / drain.
_ADMIN_CHANGE_TOKENS = (
    "SetAuthority",
    "setAuthority",
    "set_authority",
    "TransferAuthority",
    "transferAuthority",
    "transfer_authority",
    "UpgradeProgram",
    "upgradeProgram",
    "upgrade_program",
    "SetUpgradeAuthority",
    "setUpgradeAuthority",
    "set_upgrade_authority",
    "AdminWithdraw",
    "adminWithdraw",
)

# Compute-budget instruction markers (optional in UNBOUNDED_ADMIN_BUNDLE,
# but a common tell-tale because admin bundles bump CU limits).
_COMPUTE_BUDGET_TOKENS = (
    "ComputeBudgetProgram",
    "setComputeUnitLimit",
    "setComputeUnitPrice",
    "requestHeapFrame",
    "ComputeBudget::",
)

# Oracle allow-list / add-asset instruction markers.
_ORACLE_ADD_TOKENS = (
    "oracleWhitelist.push",
    "oracle_whitelist.push",
    "oracleAllowlist.push",
    "oracle_allowlist.push",
    "oracle_config.add_asset",
    "oracleConfig.addAsset",
    "add_oracle(",
    "addOracle(",
    "addCollateral(",
    "add_collateral(",
    "registerOracle(",
    "register_oracle(",
)

# Liquidity / volume precondition markers we expect near any oracle add.
_LIQUIDITY_CHECK_TOKENS = (
    "check_liquidity",
    "checkLiquidity",
    "require_liquidity",
    "requireLiquidity",
    "min_liquidity",
    "minLiquidity",
    "verify_liquidity",
    "verifyLiquidity",
    "check_volume",
    "checkVolume",
    "min_volume",
    "minVolume",
    "require_min_depth",
    "requireMinDepth",
    "liquidity_gate",
    "liquidityGate",
    "require_liquidity_floor",
    "requireLiquidityFloor",
)


def _iter_drift_scannable_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in _DRIFT_SCAN_EXTS:
            continue
        parts = set(p.parts)
        if "node_modules" in parts or ".git" in parts or "target" in parts:
            continue
        try:
            if p.stat().st_size > _DRIFT_MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def _read_lines(path: Path) -> list[str] | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return text.splitlines()


def _line_contains_any(line: str, tokens: Iterable[str]) -> bool:
    return any(t in line for t in tokens)


def _first_match_index(line: str, tokens: Iterable[str]) -> int | None:
    for t in tokens:
        if t in line:
            return line.index(t)
    return None


# ---- Rule 7: NONCE_ADVANCE_IN_MULTISIG --------------------------------------
# Detect AdvanceNonce used in the same file (within 50 lines) as a
# SetAuthority / TransferAuthority / UpgradeProgram instruction — the
# pre-signed durable-nonce pattern that enabled the Drift hack.
def _scan_nonce_advance_in_multisig(
    repo_root: Path,
) -> Iterable[tuple[Path, int, str]]:
    window = 50
    for path in _iter_drift_scannable_files(repo_root):
        lines = _read_lines(path)
        if not lines:
            continue
        nonce_hits: list[int] = []
        admin_hits: list[int] = []
        for idx, line in enumerate(lines, start=1):
            if _line_contains_any(line, _NONCE_ADVANCE_TOKENS):
                nonce_hits.append(idx)
            if _line_contains_any(line, _ADMIN_CHANGE_TOKENS):
                admin_hits.append(idx)
        if not nonce_hits or not admin_hits:
            continue
        seen_pairs: set[int] = set()
        for n in nonce_hits:
            for a in admin_hits:
                if abs(a - n) <= window and n not in seen_pairs:
                    # Report at the earlier of the two lines.
                    report_line = min(n, a)
                    seen_pairs.add(n)
                    yield (
                        path,
                        report_line,
                        f"AdvanceNonce near admin-change instruction "
                        f"(nonce line {n}, admin line {a}).",
                    )
                    break


NONCE_ADVANCE_IN_MULTISIG = Rule(
    id="NONCE_ADVANCE_IN_MULTISIG",
    severity="critical",
    description=(
        "Durable-nonce AdvanceNonce instruction built alongside a "
        "SetAuthority / TransferAuthority / UpgradeProgram instruction "
        "(within 50 lines). This is the pre-signed admin-transfer pattern "
        "used in the April 2026 Drift hack ($285M). Multisig signers "
        "should refuse to co-sign any transaction that advances a durable "
        "nonce AND mutates authorities in the same message."
    ),
    regex=None,
    scope="tree",
    tree_scan=_scan_nonce_advance_in_multisig,
)


# ---- Rule 8: LOW_LIQUIDITY_ORACLE_WHITELIST ---------------------------------
# Detect code that adds a token to an oracle allow-list without a
# preceding (within 30 lines above) liquidity / volume / depth check.
def _scan_low_liquidity_oracle_whitelist(
    repo_root: Path,
) -> Iterable[tuple[Path, int, str]]:
    back_window = 30
    for path in _iter_drift_scannable_files(repo_root):
        lines = _read_lines(path)
        if not lines:
            continue
        for idx, line in enumerate(lines, start=1):
            if not _line_contains_any(line, _ORACLE_ADD_TOKENS):
                continue
            start = max(0, idx - back_window - 1)
            preceding = lines[start : idx - 1]
            if any(
                _line_contains_any(pline, _LIQUIDITY_CHECK_TOKENS)
                for pline in preceding
            ):
                continue
            trigger = next(
                (t for t in _ORACLE_ADD_TOKENS if t in line),
                "oracle add",
            )
            yield (
                path,
                idx,
                f"Oracle allow-list mutation ({trigger}) with no "
                f"liquidity / volume / depth check in the preceding "
                f"{back_window} lines.",
            )


LOW_LIQUIDITY_ORACLE_WHITELIST = Rule(
    id="LOW_LIQUIDITY_ORACLE_WHITELIST",
    severity="high",
    description=(
        "Token added to an oracle allow-list / price-feed without a "
        "preceding liquidity / volume / depth precondition. In the April "
        "2026 Drift hack the attacker seeded a fake 'CarbonVote Token' as "
        "$100M+ of oracle-priced collateral because the allow-list path "
        "did not gate on real trading depth. Require a `check_liquidity` / "
        "`requireMinDepth` call (or equivalent) before every oracle add."
    ),
    regex=None,
    scope="tree",
    tree_scan=_scan_low_liquidity_oracle_whitelist,
)


# ---- Rule 9: UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE -----------------------------
# Detect a single tx-building code path (`.add(`, `.push(`, `instructions: [`)
# that bundles 2+ admin-level instructions (optionally with ComputeBudget).
# Heuristic: within a 40-line window we expect ≥ 2 distinct admin tokens,
# OR 1 admin token + 1 ComputeBudget token + 1 more admin token.
def _scan_unbounded_admin_bundle(
    repo_root: Path,
) -> Iterable[tuple[Path, int, str]]:
    window = 40
    add_patterns = (".add(", ".push(", "instructions:", "instructions.push(",
                    "tx.add(", "transaction.add(", "txn.add(")
    for path in _iter_drift_scannable_files(repo_root):
        lines = _read_lines(path)
        if not lines:
            continue
        # Find clusters of builder calls.
        for i, line in enumerate(lines):
            if not _line_contains_any(line, add_patterns):
                continue
            start = i
            end = min(len(lines), i + window)
            block = lines[start:end]
            admin_hits: list[tuple[int, str]] = []
            compute_hit = False
            for j, bline in enumerate(block):
                for tok in _ADMIN_CHANGE_TOKENS:
                    if tok in bline:
                        admin_hits.append((start + j + 1, tok))
                        break
                if _line_contains_any(bline, _COMPUTE_BUDGET_TOKENS):
                    compute_hit = True
            distinct_tokens = {tok for _, tok in admin_hits}
            # 2+ distinct admin tokens, OR (1 admin token appearing ≥2 times + compute budget).
            triggered = False
            if len(distinct_tokens) >= 2:
                triggered = True
            elif len(admin_hits) >= 2 and compute_hit:
                triggered = True
            if not triggered:
                continue
            first = admin_hits[0]
            snippet_tokens = ", ".join(sorted(distinct_tokens))
            yield (
                path,
                first[0],
                f"Tx builder bundles admin instructions: {snippet_tokens} "
                f"(compute_budget={'yes' if compute_hit else 'no'}).",
            )
            break  # one finding per file is enough


UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE = Rule(
    id="UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE",
    severity="high",
    description=(
        "A single transaction builder chains 2+ admin-level instructions "
        "(SetAuthority / TransferAuthority / UpgradeProgram / "
        "SetUpgradeAuthority), optionally paired with ComputeBudget. The "
        "April 2026 Drift hack bundled ComputeBudget + multiple "
        "SetAuthority instructions in one tx to drain vaults. Split admin "
        "ops across separate transactions, require hardware-wallet review "
        "of each, and reject any multisig proposal that touches more than "
        "one authority in a single message."
    ),
    regex=None,
    scope="tree",
    tree_scan=_scan_unbounded_admin_bundle,
)


# ---------------------------------------------------------------------------
# v1.2.0 additions (2026-04-25): commit-time leaks the comment / JSON / path
# rules above don't catch.  Both target real compromise vectors observed in
# the wild on Solana repos.
# ---------------------------------------------------------------------------

# Rule 10: MNEMONIC_IN_STRING — BIP39 seed phrase as a string literal (not in
# a comment).  Catches patterns like:
#     const mnemonic = "abandon abandon abandon ... about";
#     SEED_PHRASE='canyon vacant ... yellow'
#     mnemonic: str = """sister fox ... cluster zone"""
# The SEED_IN_COMMENT rule covers `// ... //` / `# ...` lines; this rule
# covers the LITERAL form which is the more common production-leak pattern.
# We require the string to look BIP39-shaped (12 / 24 lowercase words of
# 3-8 letters each) AND that the surrounding identifier hints at wallet
# usage (mnemonic / seed / phrase / wallet) to keep false positives tame.
MNEMONIC_IN_STRING_REGEX = re.compile(
    r"""(?ix)
    (?:mnemonic|seed[_\-]?phrase|seed|wallet[_\-]?phrase)   # context word
    \s*[:=]\s*                                              # = or :
    (?P<q>['"`])                                            # opening quote
    (?P<body>(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})            # 12 or 24 words
    (?P=q)                                                  # matching close
    """
)

MNEMONIC_IN_STRING = Rule(
    id="MNEMONIC_IN_STRING",
    severity="critical",
    description=(
        "BIP39-shaped seed phrase appears as a string literal assigned to "
        "a wallet/seed/mnemonic identifier. Seed phrases give full wallet "
        "control; never store as a literal in tracked code. Move to a "
        "secrets manager (1Password CLI, doppler, vault) and rotate the "
        "wallet."
    ),
    regex=MNEMONIC_IN_STRING_REGEX,
    scope="content",
)


# Rule 11: ANCHOR_WALLET_LEAK — Anchor.toml `[provider].wallet` pointing at
# a path that resolves to a file present in the repo.  This is the canonical
# Anchor framework setup leak: the local dev keypair gets committed because
# the path in Anchor.toml is repo-relative.
def _scan_anchor_wallet_leak(repo_root: Path) -> Iterable[tuple[Path, int, str]]:
    for toml in repo_root.rglob("Anchor.toml"):
        if not toml.is_file():
            continue
        try:
            text = toml.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # Find the [provider] table and a `wallet = "..."` line.
        in_provider = False
        for ln, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                in_provider = (line == "[provider]")
                continue
            if not in_provider:
                continue
            m = re.match(r'^\s*wallet\s*=\s*"([^"]+)"\s*(?:#.*)?$', raw)
            if not m:
                continue
            wallet_path = m.group(1)
            # Skip ~/-rooted absolute paths (those resolve outside the repo)
            if wallet_path.startswith(("~", "/Users/", "/home/", "C:\\", "C:/")):
                continue
            # Resolve relative to the toml's directory
            candidate = (toml.parent / wallet_path).resolve()
            try:
                candidate.relative_to(repo_root.resolve())
            except ValueError:
                continue
            if candidate.is_file():
                yield (
                    toml,
                    ln,
                    f"Anchor.toml [provider].wallet -> {wallet_path} which is committed at {candidate.relative_to(repo_root.resolve())}.",
                )


ANCHOR_WALLET_LEAK = Rule(
    id="ANCHOR_WALLET_LEAK",
    severity="critical",
    description=(
        "`Anchor.toml [provider].wallet` points to a keypair file that is "
        "present inside the repo. The Anchor framework reads this on every "
        "`anchor build/test/deploy`, so the keypair is treated as live "
        "credentials. Move the keypair outside the repo (e.g. "
        "`~/.config/solana/id.json`) and update Anchor.toml accordingly."
    ),
    regex=None,
    scope="tree",
    tree_scan=_scan_anchor_wallet_leak,
)


# ---------------------------------------------------------------------------
# v1.3.0 additions (2026-04-25 evening): hex-encoded private key literals.
# Ethereum-style EOA keys are 32 bytes (64 hex) and Solana secret-key bytes
# can be exported as 64 bytes (128 hex). Both get committed to repos by
# devs who think `0x...` strings are opaque.  Strict-match: the literal
# must be assigned to a wallet/key/secret/signer/private-named identifier
# to keep noise on log dumps and SHA-256 hashes (also 64 hex) tame.
# ---------------------------------------------------------------------------

# Rule 12: HEX_PRIVATE_KEY — 64- or 128-char hex string literal assigned to
# a wallet/key/secret identifier.  Catches:
#     const PRIVATE_KEY = "0x1234abcd...";        // 64 hex (EVM)
#     priv = '1234abcd...0xed25519...';            // 128 hex (Solana secret)
#     SIGNER_KEY=ABCDEF...0123                     // .env line, 64 or 128 hex
#     wallet_secret = b"\\x12\\x34..."             // not covered (binary form)
HEX_PRIVATE_KEY_REGEX = re.compile(
    r"""(?ix)
    (?:
        private[_\-]?key | secret[_\-]?key | priv[_\-]?key |
        wallet[_\-]?secret | signer[_\-]?key | keypair[_\-]?bytes
    )
    \s*[:=]\s*                          # = or : assignment
    ['"]?                                # optional opening quote
    (?:0x)?                              # optional 0x prefix
    [0-9a-fA-F]{64}                      # 64 hex chars (EVM-size key)
    (?:[0-9a-fA-F]{64})?                 # optional extra 64 (Solana 128-hex)
    ['"]?                                # optional closing quote
    """
)

HEX_PRIVATE_KEY = Rule(
    id="HEX_PRIVATE_KEY",
    severity="critical",
    description=(
        "A 64- or 128-character hex literal is assigned to an identifier "
        "named like a private key (private_key / secret_key / wallet_secret / "
        "signer_key / keypair_bytes). 64 hex = 32 bytes = an EVM EOA key. "
        "128 hex = 64 bytes = a Solana secret-key blob. Either way: rotate "
        "immediately and remove from git history."
    ),
    regex=HEX_PRIVATE_KEY_REGEX,
    scope="content",
)


ALL_RULES: list[Rule] = [
    PLAINTEXT_KEY,
    SEED_IN_COMMENT,
    HARDCODED_RPC,
    JSON_KEYPAIR,
    ENV_LEAK,
    SOLANA_CONFIG_KEYPAIR,
    NONCE_ADVANCE_IN_MULTISIG,
    LOW_LIQUIDITY_ORACLE_WHITELIST,
    UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE,
    MNEMONIC_IN_STRING,
    ANCHOR_WALLET_LEAK,
    HEX_PRIVATE_KEY,
]


def bip39_word_ratio(words: list[str]) -> float:
    """Return fraction of `words` that appear in our sampled BIP39 list."""
    if not words:
        return 0.0
    hits = sum(1 for w in words if w in _BIP39_SAMPLE)
    return hits / len(words)
