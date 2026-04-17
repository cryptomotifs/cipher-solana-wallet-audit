"""End-to-end tests — run the scanner against every fixture dir."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from src.audit import scan_repo
from src.report import Report, emit_annotations, emit_summary

FIXTURES = Path(__file__).parent / "fixtures"


def _rule_ids(report: Report) -> set[str]:
    return {f.rule_id for f in report.findings}


class TestCleanRepo:
    def test_zero_findings(self) -> None:
        report = scan_repo(FIXTURES / "clean-repo")
        assert report.findings == [], (
            "clean-repo fixture should produce zero findings, "
            f"got: {[f.rule_id for f in report.findings]}"
        )


class TestPlaintextKeyFixture:
    def test_detects_plaintext_key(self) -> None:
        report = scan_repo(FIXTURES / "plaintext-key")
        assert "PLAINTEXT_KEY" in _rule_ids(report)


class TestSeedphraseFixture:
    def test_detects_seed_in_comment(self) -> None:
        report = scan_repo(FIXTURES / "seedphrase-comment")
        assert "SEED_IN_COMMENT" in _rule_ids(report)


class TestEnvLeakFixture:
    def test_detects_env_not_gitignored(self) -> None:
        report = scan_repo(FIXTURES / "env-not-gitignored")
        assert "ENV_LEAK" in _rule_ids(report), (
            f"expected ENV_LEAK, got: {[f.rule_id for f in report.findings]}"
        )


class TestJsonKeypairFixture:
    def test_detects_json_keypair(self) -> None:
        report = scan_repo(FIXTURES / "json-keypair")
        # JSON keypair fixture is named id.json → hits BOTH content + path rule.
        ids = _rule_ids(report)
        assert "JSON_KEYPAIR" in ids
        assert "SOLANA_CONFIG_KEYPAIR" in ids


class TestHardcodedRpcFixture:
    def test_detects_hardcoded_rpc(self) -> None:
        report = scan_repo(FIXTURES / "hardcoded-rpc")
        assert "HARDCODED_RPC" in _rule_ids(report)


class TestDriftNoncePatternFixture:
    def test_detects_nonce_advance_with_admin(self) -> None:
        report = scan_repo(FIXTURES / "drift-nonce-pattern")
        assert "NONCE_ADVANCE_IN_MULTISIG" in _rule_ids(report), (
            f"expected NONCE_ADVANCE_IN_MULTISIG, got: "
            f"{[f.rule_id for f in report.findings]}"
        )


class TestDriftOracleWhitelistFixture:
    def test_detects_oracle_push_without_liquidity_check(self) -> None:
        report = scan_repo(FIXTURES / "drift-oracle-whitelist")
        assert "LOW_LIQUIDITY_ORACLE_WHITELIST" in _rule_ids(report), (
            f"expected LOW_LIQUIDITY_ORACLE_WHITELIST, got: "
            f"{[f.rule_id for f in report.findings]}"
        )


class TestDriftAdminBundleFixture:
    def test_detects_multi_admin_tx_bundle(self) -> None:
        report = scan_repo(FIXTURES / "drift-admin-bundle")
        assert "UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE" in _rule_ids(report), (
            f"expected UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE, got: "
            f"{[f.rule_id for f in report.findings]}"
        )


class TestCleanRepoSurvivesDriftRules:
    """Regression: the three new rules must not flag the clean fixture."""

    def test_clean_repo_still_zero(self) -> None:
        report = scan_repo(FIXTURES / "clean-repo")
        ids = _rule_ids(report)
        assert "NONCE_ADVANCE_IN_MULTISIG" not in ids
        assert "LOW_LIQUIDITY_ORACLE_WHITELIST" not in ids
        assert "UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE" not in ids


class TestReportFormatting:
    def test_annotation_format(self) -> None:
        report = scan_repo(FIXTURES / "plaintext-key")
        buf = io.StringIO()
        emit_annotations(report, FIXTURES / "plaintext-key", stream=buf)
        text = buf.getvalue()
        assert "::error" in text
        assert "PLAINTEXT_KEY" in text
        assert "file=leak.py" in text

    def test_summary_counts(self) -> None:
        report = scan_repo(FIXTURES / "plaintext-key")
        buf = io.StringIO()
        emit_summary(report, stream=buf)
        text = buf.getvalue()
        assert "Summary" in text
        assert "critical" in text


class TestMainExitCode:
    def test_critical_triggers_exit_1(self, monkeypatch, tmp_path) -> None:
        from src import audit

        monkeypatch.setenv("FAIL_ON", "high")
        monkeypatch.setenv("INCLUDE", "**/*")
        monkeypatch.setenv("EXCLUDE", ".git/**")
        monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)

        rc = audit.main([str(FIXTURES / "plaintext-key")])
        assert rc == 1

    def test_clean_repo_exits_0(self, monkeypatch) -> None:
        from src import audit

        monkeypatch.setenv("FAIL_ON", "high")
        monkeypatch.setenv("INCLUDE", "**/*")
        monkeypatch.setenv("EXCLUDE", ".git/**")
        monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)

        rc = audit.main([str(FIXTURES / "clean-repo")])
        assert rc == 0

    def test_invalid_fail_on_returns_2(self, monkeypatch) -> None:
        from src import audit

        monkeypatch.setenv("FAIL_ON", "bogus")
        rc = audit.main([str(FIXTURES / "clean-repo")])
        assert rc == 2
