"""Scanner entrypoint for the Cipher Solana Wallet Audit action.

Reads configuration from environment variables (set by the composite
action) and walks the repo applying every rule in `patterns.py`.  Writes
GitHub Actions annotations and a human-readable summary, then exits
non-zero if any finding at/above the configured severity threshold is
present.
"""

from __future__ import annotations

import fnmatch
import os
import re
import sys
from pathlib import Path
from typing import Iterable

# Support running both as `python src/audit.py` from the repo root AND as
# `python -m src.audit` or directly from the `src/` dir.
try:  # pragma: no cover - path shim
    from patterns import (  # type: ignore[import-not-found]
        ALL_RULES,
        SEVERITY_ORDER,
        Rule,
        bip39_word_ratio,
    )
    from report import Finding, Report, emit_annotations, emit_summary  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - path shim
    from src.patterns import (
        ALL_RULES,
        SEVERITY_ORDER,
        Rule,
        bip39_word_ratio,
    )
    from src.report import Finding, Report, emit_annotations, emit_summary


DEFAULT_INCLUDE = "**/*"
DEFAULT_EXCLUDE = "node_modules/**,.git/**,dist/**,build/**,vendor/**"
MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB hard cap per file
BINARY_SAMPLE_BYTES = 2048


def _split_patterns(s: str) -> list[str]:
    return [p.strip() for p in (s or "").split(",") if p.strip()]


def _matches_any(path: Path, patterns: Iterable[str], root: Path) -> bool:
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        rel = path.as_posix()
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat):
            return True
        # fnmatch treats ** the same as *, so also try first-segment match.
        if "**" in pat:
            head = pat.split("**", 1)[0].rstrip("/")
            if head and rel.startswith(head):
                return True
    return False


def _looks_binary(data: bytes) -> bool:
    if b"\x00" in data[:BINARY_SAMPLE_BYTES]:
        return True
    # Non-text ratio heuristic.
    text_bytes = bytes(range(7, 14)) + bytes(range(32, 127)) + b"\r\n\t"
    if not data:
        return False
    non_text = sum(1 for b in data[:BINARY_SAMPLE_BYTES] if b not in text_bytes)
    return (non_text / min(len(data), BINARY_SAMPLE_BYTES)) > 0.30


def _iter_files(
    root: Path, include: list[str], exclude: list[str]
) -> Iterable[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if _matches_any(p, exclude, root):
            continue
        if not include or _matches_any(p, include, root) or include == [DEFAULT_INCLUDE]:
            yield p


def _apply_content_rule(rule: Rule, path: Path, text: str) -> Iterable[Finding]:
    assert rule.regex is not None
    for idx, line in enumerate(text.splitlines(), start=1):
        for m in rule.regex.finditer(line):
            matched = m.group(0)
            # SEED_IN_COMMENT: reduce false positives with BIP39 word-ratio
            # gate — match must contain ≥ 25% recognized BIP39 words.
            if rule.id == "SEED_IN_COMMENT":
                words_group = m.group(1) if m.groups() else matched
                words = re.findall(r"[a-z]{3,8}", words_group)
                # Must be exactly 12 or 24 words to be a real seed.
                if len(words) not in (12, 24):
                    continue
                if bip39_word_ratio(words) < 0.25:
                    continue
            yield Finding(
                rule_id=rule.id,
                severity=rule.severity,
                file=path,
                line=idx,
                message=rule.description,
                snippet=line.strip()[:200],
            )


def _apply_path_rule(rule: Rule, path: Path, root: Path) -> Iterable[Finding]:
    assert rule.regex is not None
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        rel = path.as_posix()
    if rule.regex.search(rel):
        yield Finding(
            rule_id=rule.id,
            severity=rule.severity,
            file=path,
            line=1,
            message=rule.description,
            snippet=rel,
        )


def scan_repo(
    root: Path,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> Report:
    """Run every rule against `root` and return a populated Report."""
    include = include or [DEFAULT_INCLUDE]
    exclude = exclude or _split_patterns(DEFAULT_EXCLUDE)

    # Always exclude our own fixtures when scanning our own repo, so that
    # running the action on itself does not flag the deliberately bad test
    # fixtures.  Callers may override by changing `exclude`.
    report = Report()

    content_rules = [r for r in ALL_RULES if r.scope == "content"]
    path_rules = [r for r in ALL_RULES if r.scope == "path"]
    tree_rules = [r for r in ALL_RULES if r.scope == "tree"]

    for f in _iter_files(root, include, exclude):
        # Path-based rules (cheap, don't need to read file).
        for rule in path_rules:
            for finding in _apply_path_rule(rule, f, root):
                report.add(finding)
        # Content-based rules — skip binaries and oversized files.
        try:
            size = f.stat().st_size
        except OSError:
            continue
        if size == 0 or size > MAX_FILE_BYTES:
            continue
        try:
            with f.open("rb") as handle:
                head = handle.read(BINARY_SAMPLE_BYTES)
                if _looks_binary(head):
                    continue
                rest = handle.read(MAX_FILE_BYTES - len(head))
            raw = head + rest
            text = raw.decode("utf-8", errors="replace")
        except OSError:
            continue

        for rule in content_rules:
            for finding in _apply_content_rule(rule, f, text):
                report.add(finding)

    # Tree-level rules.
    for rule in tree_rules:
        if rule.tree_scan is None:
            continue
        for path, line, msg in rule.tree_scan(root):
            if _matches_any(path, exclude, root):
                continue
            report.add(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    file=path,
                    line=line,
                    message=f"{rule.description}  ({msg})",
                )
            )

    return report


def _set_github_output(key: str, value: str) -> None:
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    try:
        with open(out, "a", encoding="utf-8") as handle:
            handle.write(f"{key}={value}\n")
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    fail_on = os.environ.get("FAIL_ON", "high").strip().lower()
    if fail_on not in SEVERITY_ORDER:
        print(f"::error::invalid FAIL_ON value: {fail_on!r}", file=sys.stderr)
        return 2

    include = _split_patterns(os.environ.get("INCLUDE", DEFAULT_INCLUDE))
    exclude = _split_patterns(os.environ.get("EXCLUDE", DEFAULT_EXCLUDE))

    # Repo root = GITHUB_WORKSPACE when run inside Actions, else argv[0] or cwd.
    root_env = os.environ.get("GITHUB_WORKSPACE")
    if argv:
        root = Path(argv[0]).resolve()
    elif root_env:
        root = Path(root_env).resolve()
    else:
        root = Path.cwd().resolve()

    if not root.exists() or not root.is_dir():
        print(f"::error::scan root does not exist: {root}", file=sys.stderr)
        return 2

    report = scan_repo(root, include=include, exclude=exclude)

    emit_annotations(report, root)
    emit_summary(report)

    critical = len(report.by_severity("critical"))
    total = len(report.findings)
    _set_github_output("findings-count", str(total))
    _set_github_output("critical-count", str(critical))

    threshold = SEVERITY_ORDER[fail_on]
    worst = report.max_severity_rank(SEVERITY_ORDER)
    if worst >= threshold:
        print(
            f"::error::Audit failed — findings at/above severity '{fail_on}' present "
            f"(total={total}, critical={critical}).",
            file=sys.stderr,
        )
        return 1

    print(
        f"Audit passed — {total} finding(s), none at/above '{fail_on}'.",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
