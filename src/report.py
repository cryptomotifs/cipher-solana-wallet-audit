"""Output formatting for the Solana wallet audit.

Emits GitHub Actions workflow commands so findings show up inline on PR
diffs:

    ::error file={name},line={line}::{title}: {message}
    ::warning file={name},line={line}::{title}: {message}
    ::notice file={name},line={line}::{title}: {message}

References:
  https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Finding:
    rule_id: str
    severity: str  # low | medium | high | critical
    file: Path
    line: int
    message: str
    snippet: str = ""


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def by_severity(self, sev: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == sev]

    def max_severity_rank(self, severity_order: dict[str, int]) -> int:
        if not self.findings:
            return -1
        return max(severity_order[f.severity] for f in self.findings)


def _command_for(severity: str) -> str:
    # Map severity → GitHub annotation command.
    if severity == "critical":
        return "error"
    if severity == "high":
        return "error"
    if severity == "medium":
        return "warning"
    return "notice"


def emit_annotations(report: Report, repo_root: Path, stream=None) -> None:
    """Write GitHub workflow-command annotations for each finding."""
    out = stream or sys.stdout
    for f in report.findings:
        try:
            rel = f.file.resolve().relative_to(repo_root.resolve())
        except ValueError:
            rel = f.file
        cmd = _command_for(f.severity)
        title = f"{f.rule_id} ({f.severity})"
        # Escape newlines/cr/colons per GH Actions spec.
        msg = f.message.replace("\r", " ").replace("\n", " ")
        print(
            f"::{cmd} file={rel.as_posix()},line={f.line},title={title}::{msg}",
            file=out,
        )


def emit_summary(report: Report, stream=None) -> None:
    """Print a human-readable summary to stdout."""
    out = stream or sys.stdout
    print("", file=out)
    print("=== Cipher Solana Wallet Audit — Summary ===", file=out)
    by_sev: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in report.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    for sev in ("critical", "high", "medium", "low"):
        print(f"  {sev:>8}: {by_sev.get(sev, 0)}", file=out)
    print(f"    total: {len(report.findings)}", file=out)
    print("", file=out)
    for f in report.findings:
        try:
            rel = f.file.as_posix()
        except Exception:
            rel = str(f.file)
        print(f"  [{f.severity.upper()}] {f.rule_id}", file=out)
        print(f"    {rel}:{f.line}  {f.message}", file=out)
        if f.snippet:
            print(f"    > {f.snippet[:200]}", file=out)
    print("", file=out)
