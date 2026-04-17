"""Unit tests for src/patterns.py rules."""

from __future__ import annotations

from src.patterns import (
    HARDCODED_RPC,
    JSON_KEYPAIR,
    PLAINTEXT_KEY,
    SEED_IN_COMMENT,
    SOLANA_CONFIG_KEYPAIR,
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
