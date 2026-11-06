from __future__ import annotations

import pytest
from conftest import stubbed_client

from aws_elasticache_audit.collect import CollectError, collect_region
from aws_elasticache_audit.model import EngineVersions
from aws_elasticache_audit.rules import (
    RULES,
    evaluate,
    is_supported,
    oldest_supported,
    version_key,
)


def findings_for(fixture: str):
    client, stubber, region = stubbed_client(fixture)
    try:
        inv = collect_region(client, region)
    finally:
        stubber.deactivate()
    return inv, evaluate(inv)


def rules_for(findings, resource_id: str) -> set[str]:
    return {f.rule for f in findings if f.resource_id == resource_id}


def test_healthy_region_is_clean():
    inv, findings = findings_for("healthy")
    assert [g.id for g in inv.groups] == ["prod-sessions"]
    assert findings == []


def test_group_borrows_engine_version_from_its_members():
    inv, _ = findings_for("healthy")
    group = inv.groups[0]
    # DescribeReplicationGroups does not return EngineVersion at all.
    assert group.engine_version == "7.1.0"
    assert group.node_count == 3
    assert group.availability_zones == ["eu-central-1a", "eu-central-1b", "eu-central-1c"]


def test_single_node_group_reports_no_replica_and_not_a_failover_fault():
    _, findings = findings_for("risky")
    rules = rules_for(findings, "prod-sessions-single")
    assert "GROUP_SINGLE_NODE" in rules
    assert "GROUP_NO_AUTOMATIC_FAILOVER" not in rules

    single = next(f for f in findings if f.rule == "GROUP_SINGLE_NODE")
    assert single.severity == "high"
    assert "no replica to promote" in single.detail
    assert single.members == ["prod-sessions-single-001"]


def test_single_node_group_reports_the_rest_of_its_faults():
    _, findings = findings_for("risky")
    assert rules_for(findings, "prod-sessions-single") == {
        "GROUP_SINGLE_NODE",
        "GROUP_NO_TRANSIT_ENCRYPTION",
        "GROUP_NO_AUTH_TOKEN",
        "GROUP_NO_AT_REST_ENCRYPTION",
        "NO_SNAPSHOT_RETENTION",
        "NO_AUTO_MINOR_UPGRADE",
    }


def test_group_with_a_replica_and_failover_off_is_a_failover_fault():
    _, findings = findings_for("risky")
    rules = rules_for(findings, "legacy-cart")
    assert "GROUP_NO_AUTOMATIC_FAILOVER" in rules
    assert "GROUP_SINGLE_NODE" not in rules

    failover = next(
        f
        for f in findings
        if f.rule == "GROUP_NO_AUTOMATIC_FAILOVER" and f.resource_id == "legacy-cart"
    )
    assert "--automatic-failover-enabled" in failover.remediation


def test_unsupported_engine_version_names_the_upgrade_target():
    _, findings = findings_for("risky")
    eol = next(
        f
        for f in findings
        if f.rule == "ENGINE_VERSION_UNSUPPORTED" and f.resource_id == "legacy-cart"
    )
    assert eol.severity == "high"
    assert "5.0.6" in eol.detail
    assert "oldest version AWS still supports for redis is 6.2" in eol.detail
    assert "--engine-version 6.2" in eol.remediation


def test_standalone_redis_node_is_an_orphan_with_no_backup():
    _, findings = findings_for("risky")
    assert rules_for(findings, "adhoc-redis") == {
        "CLUSTER_ORPHAN_NODE",
        "NO_SNAPSHOT_RETENTION",
    }


def test_memcached_cluster_is_not_judged_on_redis_features():
    _, findings = findings_for("risky")
    # No auth token, no snapshots and no replication group are normal for memcached.
    assert rules_for(findings, "page-fragments") == set()


def test_group_members_do_not_produce_cluster_level_findings():
    _, findings = findings_for("risky")
    for member in ("prod-sessions-single-001", "legacy-cart-001", "legacy-cart-002"):
        assert rules_for(findings, member) == set()


def test_three_single_node_shards_are_one_finding_with_three_members():
    _, findings = findings_for("sharded")
    singles = [f for f in findings if f.rule == "GROUP_SINGLE_NODE"]
    assert len(singles) == 1
    assert singles[0].members == [
        "catalog-shards-0001-001",
        "catalog-shards-0002-001",
        "catalog-shards-0003-001",
    ]
    assert "3 shards with a single member cluster" in singles[0].detail


def test_denied_describe_replication_groups_raises_collect_error():
    client, stubber, region = stubbed_client(
        "risky",
        errors={"describe_replication_groups": ("AccessDenied", "not authorized")},
    )
    try:
        with pytest.raises(CollectError) as excinfo:
            collect_region(client, region)
    finally:
        stubber.deactivate()
    assert "AccessDenied" in str(excinfo.value)
    assert "DescribeReplicationGroups" in str(excinfo.value)


def test_denied_engine_versions_only_drops_that_one_rule():
    client, stubber, region = stubbed_client(
        "risky",
        errors={"describe_cache_engine_versions": ("AccessDenied", "not authorized")},
    )
    try:
        inv = collect_region(client, region)
    finally:
        stubber.deactivate()

    assert inv.engine_versions is None
    assert len(inv.warnings) == 1
    assert "DescribeCacheEngineVersions" in inv.warnings[0]

    findings = evaluate(inv)
    assert not [f for f in findings if f.rule == "ENGINE_VERSION_UNSUPPORTED"]
    assert "GROUP_SINGLE_NODE" in {f.rule for f in findings}


@pytest.mark.parametrize(
    "version,expected",
    [
        ("7.1.0", True),
        ("7.1", True),
        ("7.0.7", True),
        ("5.0.6", False),
        ("4.0.10", False),
        ("", True),
    ],
)
def test_is_supported_matches_on_the_version_line(version, expected):
    versions = EngineVersions(by_engine={"redis": ["6.2", "7.0", "7.1"]})
    assert is_supported("redis", version, versions) is expected


def test_oldest_supported_sorts_numerically_not_lexically():
    versions = EngineVersions(by_engine={"redis": ["7.1", "10.0", "6.2"]})
    assert oldest_supported("redis", versions) == "6.2"
    assert oldest_supported("valkey", versions) == ""


def test_version_key_tolerates_junk():
    assert version_key("7.1.0") == (7, 1, 0)
    assert version_key("6.x") == (6, 0)


def test_every_rule_has_a_known_severity():
    assert set(RULES.values()) <= {"high", "medium", "low"}
