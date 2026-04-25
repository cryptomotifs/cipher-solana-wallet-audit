"""Unit tests for src/patterns.py rules."""

from __future__ import annotations

from src.patterns import (
    ALL_RULES,
    ANCHOR_WALLET_LEAK,
    HARDCODED_RPC,
    JSON_KEYPAIR,
    LOW_LIQUIDITY_ORACLE_WHITELIST,
    MNEMONIC_IN_STRING,
    NONCE_ADVANCE_IN_MULTISIG,
    PLAINTEXT_KEY,
    SEED_IN_COMMENT,
    SOLANA_CONFIG_KEYPAIR,
    UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE,
    bip39_word_ratio,
)


class TestPlaintextKey:
    def test_matches_88_base58_chars(self) -> None:
        # Synthetic 88-char string using valid base58 alphabet (no 0 O I l).
        candidate = "sAm" * 29 + "s"  # 88 chars
        assert len(candidate) == 88
        assert PLAINTEXT_KEY.regex.search(candidate) is not None

    def test_matches_min_86(self) -> None:
        candidate = "a" * 86
        assert PLAINTEXT_KEY.regex.search(candidate) is not None

    def test_skips_85(self) -> None:
        assert PLAINTEXT_KEY.regex.search("a" * 85) is None

    def test_skips_91(self) -> None:
        # Boundaries: 91 still contains an 86-90 substring, so it should match.
        # Rule is "contains 86..90 run"; 91 chars is still detected, but
        # that is the intended behaviour (a key might be embedded in text).
        assert PLAINTEXT_KEY.regex.search("a" * 91) is not None

    def test_skips_excluded_chars(self) -> None:
        # 0, O, I, l are NOT in base58 alphabet.
        assert PLAINTEXT_KEY.regex.search("0" * 88) is None
        assert PLAINTEXT_KEY.regex.search("O" * 88) is None
        assert PLAINTEXT_KEY.regex.search("I" * 88) is None
        assert PLAINTEXT_KEY.regex.search("l" * 88) is None


class TestJsonKeypair:
    def test_matches_64_int_array(self) -> None:
        arr = "[" + ",".join(["12"] * 64) + "]"
        assert JSON_KEYPAIR.regex.search(arr) is not None

    def test_matches_with_whitespace(self) -> None:
        arr = "[ " + ", ".join(["255"] * 64) + " ]"
        assert JSON_KEYPAIR.regex.search(arr) is not None

    def test_skips_63_ints(self) -> None:
        arr = "[" + ",".join(["12"] * 63) + "]"
        assert JSON_KEYPAIR.regex.search(arr) is None

    def test_skips_mixed_non_int(self) -> None:
        arr = "[" + ",".join(["1.5"] * 64) + "]"
        assert JSON_KEYPAIR.regex.search(arr) is None


class TestSeedInComment:
    def test_matches_12_word_python_comment(self) -> None:
        line = (
            "# abandon ability able about above absent "
            "absorb abstract absurd abuse access accident"
        )
        assert SEED_IN_COMMENT.regex.search(line) is not None

    def test_matches_js_comment(self) -> None:
        line = (
            "// abandon ability able about above absent "
            "absorb abstract absurd abuse access accident"
        )
        assert SEED_IN_COMMENT.regex.search(line) is not None

    def test_skips_non_comment(self) -> None:
        # No comment marker → no match.
        line = "abandon ability able about above absent absorb abstract absurd abuse access accident"
        assert SEED_IN_COMMENT.regex.search(line) is None


class TestBip39Ratio:
    def test_all_bip39(self) -> None:
        words = ["abandon", "ability", "able", "about"]
        assert bip39_word_ratio(words) == 1.0

    def test_none_bip39(self) -> None:
        # Use truly-unrecognised tokens (none in our sampled BIP39 set).
        words = ["xylo", "zyrg", "qqqq", "plzt"]
        assert bip39_word_ratio(words) == 0.0

    def test_empty(self) -> None:
        assert bip39_word_ratio([]) == 0.0


class TestHardcodedRpc:
    def test_matches_mainnet_helius_with_api_key(self) -> None:
        url = "https://mainnet-beta.helius-rpc.com/?api-key=fake1234"
        assert HARDCODED_RPC.regex.search(url) is not None

    def test_matches_mainnet_with_token(self) -> None:
        url = "https://mainnet-rpc.example.com/token/deadbeef"
        assert HARDCODED_RPC.regex.search(url) is not None

    def test_skips_plain_mainnet_rpc(self) -> None:
        # Public endpoint with no credential is fine.
        url = "https://api.mainnet-beta.solana.com"
        assert HARDCODED_RPC.regex.search(url) is None


class TestSolanaConfigKeypair:
    def test_matches_id_json(self) -> None:
        assert SOLANA_CONFIG_KEYPAIR.regex.search("config/id.json") is not None

    def test_matches_wallet_keypair_json(self) -> None:
        assert SOLANA_CONFIG_KEYPAIR.regex.search("keys/wallet-keypair.json") is not None

    def test_skips_unrelated_json(self) -> None:
        assert SOLANA_CONFIG_KEYPAIR.regex.search("package.json") is None


class TestDriftRulesRegistered:
    """All three drift-hack-derived rules are exported through ALL_RULES."""

    def test_nonce_rule_registered(self) -> None:
        assert NONCE_ADVANCE_IN_MULTISIG in ALL_RULES
        assert NONCE_ADVANCE_IN_MULTISIG.scope == "tree"
        assert NONCE_ADVANCE_IN_MULTISIG.severity == "critical"
        assert NONCE_ADVANCE_IN_MULTISIG.tree_scan is not None

    def test_oracle_rule_registered(self) -> None:
        assert LOW_LIQUIDITY_ORACLE_WHITELIST in ALL_RULES
        assert LOW_LIQUIDITY_ORACLE_WHITELIST.scope == "tree"
        assert LOW_LIQUIDITY_ORACLE_WHITELIST.severity == "high"
        assert LOW_LIQUIDITY_ORACLE_WHITELIST.tree_scan is not None

    def test_admin_bundle_rule_registered(self) -> None:
        assert UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE in ALL_RULES
        assert UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE.scope == "tree"
        assert UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE.severity == "high"
        assert UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE.tree_scan is not None


# ---------------------------------------------------------------------------
# v1.2.0 — MNEMONIC_IN_STRING and ANCHOR_WALLET_LEAK
# ---------------------------------------------------------------------------


class TestMnemonicInString:
    def test_matches_12_word_string_double_quoted(self) -> None:
        line = (
            'const mnemonic = "abandon ability able about above absent absorb '
            'abstract absurd abuse access accident";'
        )
        assert MNEMONIC_IN_STRING.regex.search(line) is not None

    def test_matches_12_word_string_single_quoted(self) -> None:
        line = (
            "SEED_PHRASE='canyon vacant velvet venture verb very vessel veteran "
            "viable vibrant vicious victory'"
        )
        assert MNEMONIC_IN_STRING.regex.search(line) is not None

    def test_matches_24_words_typescript_assignment(self) -> None:
        words = " ".join(["abandon"] * 24)
        line = f"const seed = `{words}`;"
        assert MNEMONIC_IN_STRING.regex.search(line) is not None

    def test_skips_when_context_word_is_unrelated(self) -> None:
        # No mnemonic / seed / wallet context near the literal — no match.
        words = " ".join(["abandon"] * 12)
        line = f'const message = "{words}";'
        assert MNEMONIC_IN_STRING.regex.search(line) is None

    def test_skips_too_few_words(self) -> None:
        words = " ".join(["abandon"] * 11)
        line = f'const mnemonic = "{words}";'
        assert MNEMONIC_IN_STRING.regex.search(line) is None

    def test_skips_too_many_words(self) -> None:
        # 25 words inside the quotes — the regex requires the body to be
        # 12..24 words and immediately close with the matching quote, so a
        # 25-word string is NOT matched.  This is the strict-match property
        # that keeps false positives low on long natural-language strings.
        words = " ".join(["abandon"] * 25)
        line = f'const mnemonic = "{words}";'
        assert MNEMONIC_IN_STRING.regex.search(line) is None

    def test_severity_and_registration(self) -> None:
        assert MNEMONIC_IN_STRING in ALL_RULES
        assert MNEMONIC_IN_STRING.severity == "critical"
        assert MNEMONIC_IN_STRING.scope == "content"


class TestAnchorWalletLeak:
    """Exercise the tree-scan against a synthetic mini-repo on tmp_path."""

    def _write_anchor_repo(self, tmp_path, wallet_path: str, wallet_present: bool):
        anchor = tmp_path / "Anchor.toml"
        anchor.write_text(
            "[provider]\n"
            f'wallet = "{wallet_path}"\n'
            'cluster = "Localnet"\n',
            encoding="utf-8",
        )
        if wallet_present:
            target = (tmp_path / wallet_path).resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            # Synthetic 64-int array (matches the real Solana CLI keypair shape)
            target.write_text("[" + ",".join(["12"] * 64) + "]", encoding="utf-8")
        return anchor

    def test_flags_when_wallet_path_resolves_inside_repo(self, tmp_path) -> None:
        self._write_anchor_repo(tmp_path, "./id.json", wallet_present=True)
        results = list(ANCHOR_WALLET_LEAK.tree_scan(tmp_path))
        assert len(results) == 1
        path, line, msg = results[0]
        assert path.name == "Anchor.toml"
        assert line == 2
        assert "id.json" in msg

    def test_skips_when_wallet_outside_repo(self, tmp_path) -> None:
        # Path leaving the repo via .. — resolved would land outside tmp_path.
        self._write_anchor_repo(tmp_path, "../outside_keypair.json", wallet_present=False)
        results = list(ANCHOR_WALLET_LEAK.tree_scan(tmp_path))
        assert results == []

    def test_skips_home_dir_path(self, tmp_path) -> None:
        self._write_anchor_repo(tmp_path, "~/.config/solana/id.json", wallet_present=False)
        results = list(ANCHOR_WALLET_LEAK.tree_scan(tmp_path))
        assert results == []

    def test_skips_when_file_missing(self, tmp_path) -> None:
        self._write_anchor_repo(tmp_path, "./id.json", wallet_present=False)
        results = list(ANCHOR_WALLET_LEAK.tree_scan(tmp_path))
        assert results == []

    def test_skips_when_wallet_in_other_table(self, tmp_path) -> None:
        # `wallet = ...` under [scripts] not [provider] is irrelevant.
        anchor = tmp_path / "Anchor.toml"
        anchor.write_text(
            "[scripts]\n"
            'wallet = "./id.json"\n',
            encoding="utf-8",
        )
        # Create the file too — should still NOT flag.
        (tmp_path / "id.json").write_text("[" + ",".join(["1"] * 64) + "]")
        results = list(ANCHOR_WALLET_LEAK.tree_scan(tmp_path))
        assert results == []

    def test_severity_and_registration(self) -> None:
        assert ANCHOR_WALLET_LEAK in ALL_RULES
        assert ANCHOR_WALLET_LEAK.severity == "critical"
        assert ANCHOR_WALLET_LEAK.scope == "tree"
        assert ANCHOR_WALLET_LEAK.tree_scan is not None
