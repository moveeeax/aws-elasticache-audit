from __future__ import annotations

import csv
import io
import json

import pytest
from conftest import FakeEc2, FakeSession, stubbed_client

from aws_elasticache_audit.cli import main


def run(argv, fixture="risky", errors=None, extra_clients=None):
    client, stubber, region = stubbed_client(fixture, errors=errors)
    clients = {"elasticache": client}
    clients.update(extra_clients or {})
    session = FakeSession(clients, region_name=region)
    try:
        code = main(argv, session=session)
    finally:
        stubber.deactivate()
    return code


def test_clean_region_exits_zero(capsys):
    code = run(["--region", "eu-central-1"], fixture="healthy")
    out = capsys.readouterr().out
    assert code == 0
    assert "No findings" in out
    assert "1 replication group(s)" in out


def test_findings_at_high_exit_one(capsys):
    code = run(["--region", "eu-central-1"])
    out = capsys.readouterr().out
    assert code == 1
    assert "GROUP_SINGLE_NODE" in out
    assert "prod-sessions-single" in out
    assert "fix (not in place)" in out  # transit encryption needs a new group


def test_fail_on_threshold_respects_severity(capsys):
    argv = ["--region", "eu-central-1", "--ignore", "GROUP_SINGLE_NODE,GROUP_NO_TRANSIT_ENCRYPTION,"
            "ENGINE_VERSION_UNSUPPORTED,GROUP_NO_AUTOMATIC_FAILOVER"]
    assert run(argv + ["--fail-on", "high"]) == 0
    capsys.readouterr()
    assert run(argv + ["--fail-on", "medium"]) == 1
    capsys.readouterr()


def test_fail_on_never_always_exits_zero(capsys):
    assert run(["--region", "eu-central-1", "--fail-on", "never"]) == 0
    capsys.readouterr()


def test_ignore_drops_the_rule_from_the_output(capsys):
    code = run(["--region", "eu-central-1", "--format", "json", "--ignore", "group_single_node"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert "GROUP_SINGLE_NODE" not in {f["rule"] for f in payload["findings"]}


def test_unknown_ignore_rule_exits_two(capsys):
    code = run(["--region", "eu-central-1", "--ignore", "NO_SUCH_RULE"])
    err = capsys.readouterr().err
    assert code == 2
    assert "unknown rule(s) in --ignore: NO_SUCH_RULE" in err


def test_json_output_carries_a_summary(capsys):
    run(["--region", "eu-central-1", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    summary = payload["summary"]
    assert summary["total"] == len(payload["findings"])
    assert summary["high"] + summary["medium"] + summary["low"] == summary["total"]
    assert summary["regionsScanned"] == 1
    assert payload["warnings"] == []


def test_csv_output_is_parseable(capsys):
    run(["--region", "eu-central-1", "--format", "csv"])
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert rows
    assert rows[0]["severity"] in {"high", "medium", "low"}
    assert {"rule", "resource_id", "remediation"} <= set(rows[0])


def test_group_filter_narrows_the_scan(capsys):
    code = run(["--region", "eu-central-1", "--format", "json", "--group", "legacy-cart"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert {f["resourceId"] for f in payload["findings"]} == {"legacy-cart"}


def test_engine_filter_keeps_only_that_engine(capsys):
    code = run(["--region", "eu-central-1", "--format", "json", "--engine", "memcached"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["findings"] == []


def test_all_regions_uses_describe_regions(capsys):
    code = run(
        ["--all-regions", "--format", "json"],
        extra_clients={"ec2": FakeEc2(["eu-central-1"])},
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["summary"]["regionsScanned"] == 1


def test_api_denial_exits_two_without_a_traceback(capsys):
    code = run(
        ["--region", "eu-central-1"],
        errors={"describe_replication_groups": ("AccessDenied", "not authorized")},
    )
    captured = capsys.readouterr()
    assert code == 2
    assert captured.err.startswith("error: ")
    assert "Traceback" not in captured.err
    assert captured.out == ""


def test_engine_version_denial_warns_and_keeps_scanning(capsys):
    code = run(
        ["--region", "eu-central-1"],
        errors={"describe_cache_engine_versions": ("AccessDenied", "not authorized")},
    )
    out = capsys.readouterr().out
    assert code == 1
    assert out.startswith("warning: ")
    assert "ENGINE_VERSION_UNSUPPORTED" in out.splitlines()[0]
    assert "GROUP_SINGLE_NODE" in out


def test_missing_region_exits_two(capsys):
    client, stubber, _ = stubbed_client("healthy")
    session = FakeSession({"elasticache": client}, region_name=None)
    try:
        code = main([], session=session)
    finally:
        stubber.deactivate()
    assert code == 2
    assert "no region" in capsys.readouterr().err


def test_list_rules_prints_every_rule(capsys):
    assert main(["--list-rules"], session=None) == 0
    out = capsys.readouterr().out
    assert "high   GROUP_SINGLE_NODE" in out
    assert len(out.strip().splitlines()) == 9


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
