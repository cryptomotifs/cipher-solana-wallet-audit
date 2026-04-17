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


ALL_RULES: list[Rule] = [
    PLAINTEXT_KEY,
    SEED_IN_COMMENT,
    HARDCODED_RPC,
    JSON_KEYPAIR,
    ENV_LEAK,
    SOLANA_CONFIG_KEYPAIR,
]


def bip39_word_ratio(words: list[str]) -> float:
    """Return fraction of `words` that appear in our sampled BIP39 list."""
    if not words:
        return 0.0
    hits = sum(1 for w in words if w in _BIP39_SAMPLE)
    return hits / len(words)
