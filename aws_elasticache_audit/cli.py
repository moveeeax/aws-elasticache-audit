"""Command line entry point: flags, region fan-out, exit codes."""

from __future__ import annotations

import argparse
import sys

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from . import __version__
from .collect import CollectError, collect_region, enabled_regions
from .model import Finding, severity_rank
from .report import render
from .rules import RULES, evaluate

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-elasticache-audit",
        description=(
            "Audit ElastiCache replication groups and cache clusters for the settings "
            "that turn losing one node into an incident."
        ),
    )
    parser.add_argument("--profile", help="AWS named profile to use")
    parser.add_argument(
        "--region",
        action="append",
        default=[],
        metavar="REGION",
        help="region to scan; repeatable",
    )
    parser.add_argument(
        "--all-regions",
        action="store_true",
        help="scan every region enabled for the account (EC2 DescribeRegions)",
    )
    parser.add_argument(
        "--group",
        action="append",
        default=[],
        metavar="ID",
        help="limit to this replication group id (or a cluster of it); repeatable",
    )
    parser.add_argument(
        "--engine",
        choices=["redis", "memcached"],
        help="limit to one engine",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        dest="fmt",
    )
    parser.add_argument(
        "--fail-on",
        choices=["high", "medium", "low", "never"],
        default="high",
        help="lowest severity that makes the exit code 1 (default: high)",
    )
    parser.add_argument(
        "--ignore",
        default="",
        metavar="RULE,RULE",
        help="comma separated rules to drop from the output and the exit code",
    )
    parser.add_argument("--list-rules", action="store_true", help="print the rules and exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def parse_ignore(raw: str) -> list[str]:
    wanted = [item.strip().upper() for item in raw.split(",") if item.strip()]
    unknown = [item for item in wanted if item not in RULES]
    if unknown:
        raise ValueError(f"unknown rule(s) in --ignore: {', '.join(unknown)}")
    return wanted


def _keep_group(group, wanted_groups: list[str], engine: str | None) -> bool:
    if engine and group.engine != engine:
        return False
    if wanted_groups and group.id not in wanted_groups:
        return False
    return True


def _keep_cluster(cluster, wanted_groups: list[str], engine: str | None) -> bool:
    if engine and cluster.engine != engine:
        return False
    if wanted_groups:
        return cluster.replication_group_id in wanted_groups or cluster.id in wanted_groups
    return True


def exit_code(findings: list[Finding], fail_on: str) -> int:
    if fail_on == "never" or not findings:
        return EXIT_CLEAN
    threshold = severity_rank(fail_on)
    worst = max(severity_rank(f.severity) for f in findings)
    return EXIT_FINDINGS if worst >= threshold else EXIT_CLEAN


def scan(session, regions: list[str], args) -> tuple[list[Finding], list[str], dict[str, int]]:
    findings: list[Finding] = []
    warnings: list[str] = []
    scanned = {"groups": 0, "clusters": 0, "regions": 0}
    ignore = parse_ignore(args.ignore)

    for region in regions:
        client = session.client("elasticache", region_name=region)
        inv = collect_region(client, region)
        inv.groups = [g for g in inv.groups if _keep_group(g, args.group, args.engine)]
        inv.clusters = [c for c in inv.clusters if _keep_cluster(c, args.group, args.engine)]
        scanned["groups"] += len(inv.groups)
        scanned["clusters"] += len([c for c in inv.clusters if c.standalone])
        scanned["regions"] += 1
        warnings.extend(inv.warnings)
        findings.extend(f for f in evaluate(inv) if f.rule not in ignore)

    return findings, warnings, scanned


def resolve_regions(session, args) -> list[str]:
    if args.all_regions:
        return enabled_regions(session.client("ec2", region_name=_bootstrap_region(session)))
    if args.region:
        seen = []
        for region in args.region:
            if region not in seen:
                seen.append(region)
        return seen
    region = session.region_name
    if not region:
        raise CollectError(
            "no region: pass --region, --all-regions, or set AWS_REGION / a profile region"
        )
    return [region]


def _bootstrap_region(session) -> str:
    return session.region_name or "us-east-1"


def main(argv: list[str] | None = None, session=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        for rule, severity in sorted(RULES.items(), key=lambda kv: (-severity_rank(kv[1]), kv[0])):
            print(f"{severity:<6} {rule}")
        return EXIT_CLEAN

    try:
        parse_ignore(args.ignore)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if session is None:
        import boto3

        session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()

    try:
        regions = resolve_regions(session, args)
        findings, warnings, scanned = scan(session, regions, args)
    except CollectError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except NoCredentialsError:
        print("error: no AWS credentials found", file=sys.stderr)
        return EXIT_ERROR
    except ClientError as exc:
        err = exc.response.get("Error", {})
        print(
            f"error: {err.get('Code', 'ClientError')}: {err.get('Message', str(exc))}",
            file=sys.stderr,
        )
        return EXIT_ERROR
    except BotoCoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(render(args.fmt, findings, warnings, scanned))
    return exit_code(findings, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
