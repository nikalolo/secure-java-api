#!/usr/bin/env python3
"""Turn one or more Trivy JSON reports into a Markdown summary.

Usage:
    trivy_report.py LABEL=report.json [LABEL=report.json ...] [--top N]

With one report: severity counts plus the top CRITICAL/HIGH findings.
With several: a side-by-side comparison table (e.g. baseline vs hardened).

Standard library only, so it runs on any CI runner without installs.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


@dataclass(frozen=True)
class Finding:
    vuln_id: str
    severity: str
    pkg: str
    installed: str
    fixed: str
    target: str


def load_findings(report: dict) -> list[Finding]:
    """Flatten Trivy's Results[].Vulnerabilities[] into Finding objects.

    The same CVE can appear in several targets (e.g. OS layer and a JAR);
    each occurrence is kept because each needs its own fix.
    """
    findings = []
    for result in report.get("Results") or []:
        target = result.get("Target", "?")
        for v in result.get("Vulnerabilities") or []:
            severity = v.get("Severity", "UNKNOWN").upper()
            if severity not in SEVERITIES:
                severity = "UNKNOWN"
            findings.append(
                Finding(
                    vuln_id=v.get("VulnerabilityID", "?"),
                    severity=severity,
                    pkg=v.get("PkgName", "?"),
                    installed=v.get("InstalledVersion", "?"),
                    fixed=v.get("FixedVersion", ""),
                    target=target,
                )
            )
    return findings


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    return counts


def fixable(findings: list[Finding]) -> int:
    return sum(1 for f in findings if f.fixed)


def image_name(report: dict) -> str:
    return report.get("ArtifactName", "unknown image")


def single_report(label: str, report: dict, top: int) -> str:
    findings = load_findings(report)
    counts = count_by_severity(findings)
    lines = [
        f"## Trivy: {label} (`{image_name(report)}`)",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    lines += [f"| {s} | {counts[s]} |" for s in SEVERITIES]
    lines += [
        f"| **Total** | **{len(findings)}** |",
        "",
        f"Findings with a fixed version available: {fixable(findings)} of {len(findings)}",
    ]

    serious = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    serious.sort(key=lambda f: (SEVERITIES.index(f.severity), f.vuln_id))
    if serious:
        lines += [
            "",
            f"### Top {min(top, len(serious))} CRITICAL/HIGH",
            "",
            "| ID | Severity | Package | Installed | Fixed in | Target |",
            "|---|---|---|---|---|---|",
        ]
        for f in serious[:top]:
            lines.append(
                f"| {f.vuln_id} | {f.severity} | {f.pkg} | {f.installed} "
                f"| {f.fixed or 'no fix yet'} | {f.target} |"
            )
    return "\n".join(lines)


def comparison(reports: list[tuple[str, dict]]) -> str:
    counts = [(label, count_by_severity(load_findings(r))) for label, r in reports]
    header = "| Severity | " + " | ".join(label for label, _ in counts) + " |"
    sep = "|---|" + "---|" * len(counts)
    lines = ["## Image comparison", "", header, sep]
    for s in SEVERITIES:
        lines.append(f"| {s} | " + " | ".join(str(c[s]) for _, c in counts) + " |")
    totals = " | ".join(f"**{sum(c.values())}**" for _, c in counts)
    lines.append(f"| **Total** | {totals} |")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("reports", nargs="+", metavar="LABEL=FILE")
    p.add_argument("--top", type=int, default=10, help="CRITICAL/HIGH rows to list")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    loaded = []
    for spec in args.reports:
        label, sep, path = spec.partition("=")
        if not sep or not label or not path:
            print(f"error: expected LABEL=FILE, got {spec!r}", file=sys.stderr)
            return 2
        try:
            loaded.append((label, json.loads(Path(path).read_text())))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 2

    parts = [single_report(label, r, args.top) for label, r in loaded]
    if len(loaded) > 1:
        parts.insert(0, comparison(loaded))
    print("\n\n".join(parts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
