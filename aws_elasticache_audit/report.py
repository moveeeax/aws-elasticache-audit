"""Renderers: table for a human, json for a pipeline, csv for a spreadsheet."""

from __future__ import annotations

import csv
import io
import json

from .model import Finding, severity_rank

CSV_COLUMNS = [
    "rule",
    "severity",
    "region",
    "resource_type",
    "resource_id",
    "engine",
    "engine_version",
    "node_count",
    "availability_zones",
    "members",
    "in_place",
    "detail",
    "remediation",
]


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (f.region, -severity_rank(f.severity), f.resource_id, f.rule),
    )


def counts(findings: list[Finding]) -> dict[str, int]:
    out = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        out[f.severity] += 1
    return out


def render_table(findings: list[Finding], warnings: list[str], scanned: dict[str, int]) -> str:
    lines: list[str] = []
    for warning in warnings:
        lines.append(f"warning: {warning}")
    if warnings:
        lines.append("")

    if not findings:
        lines.append(
            "No findings. Scanned {g} replication group(s) and {c} cache cluster(s) "
            "across {r} region(s).".format(
                g=scanned.get("groups", 0),
                c=scanned.get("clusters", 0),
                r=scanned.get("regions", 0),
            )
        )
        return "\n".join(lines)

    region = None
    for f in sort_findings(findings):
        if f.region != region:
            region = f.region
            lines.append(f"{region}")
        version = f.engine_version or "unknown version"
        lines.append(
            f"  {f.severity.upper():<6} {f.rule:<28} {f.resource_id} "
            f"({f.engine} {version}, {f.node_count} node(s))"
        )
        lines.append(f"         {f.detail}")
        if f.members:
            lines.append(f"         members: {', '.join(f.members)}")
        prefix = "fix" if f.in_place else "fix (not in place)"
        lines.append(f"         {prefix}: {f.remediation}")
        lines.append("")

    c = counts(findings)
    lines.append(
        "{n} finding(s): {h} high, {m} medium, {l} low across {g} replication group(s) "
        "and {cl} cache cluster(s) in {r} region(s).".format(
            n=len(findings),
            h=c["high"],
            m=c["medium"],
            l=c["low"],
            g=scanned.get("groups", 0),
            cl=scanned.get("clusters", 0),
            r=scanned.get("regions", 0),
        )
    )
    return "\n".join(lines)


def render_json(findings: list[Finding], warnings: list[str], scanned: dict[str, int]) -> str:
    payload = {
        "findings": [f.as_dict() for f in sort_findings(findings)],
        "summary": {
            "total": len(findings),
            **counts(findings),
            "replicationGroupsScanned": scanned.get("groups", 0),
            "cacheClustersScanned": scanned.get("clusters", 0),
            "regionsScanned": scanned.get("regions", 0),
        },
        "warnings": warnings,
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def render_csv(findings: list[Finding], warnings: list[str], scanned: dict[str, int]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for f in sort_findings(findings):
        writer.writerow(
            [
                f.rule,
                f.severity,
                f.region,
                f.resource_type,
                f.resource_id,
                f.engine,
                f.engine_version,
                f.node_count,
                " ".join(f.availability_zones),
                " ".join(f.members),
                "true" if f.in_place else "false",
                f.detail,
                f.remediation,
            ]
        )
    return buf.getvalue().rstrip("\n")


RENDERERS = {"table": render_table, "json": render_json, "csv": render_csv}


def render(fmt: str, findings: list[Finding], warnings: list[str], scanned: dict[str, int]) -> str:
    return RENDERERS[fmt](findings, warnings, scanned)
