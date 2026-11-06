"""Reads one region of ElastiCache into the plain shapes in model.py.

Every AWS call lives here so the rules stay pure and the tests can stub a
botocore client instead of mocking business logic.
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from .model import (
    CacheCluster,
    EngineVersions,
    Inventory,
    NodeGroup,
    ReplicationGroup,
)


class CollectError(Exception):
    """An AWS call the scan cannot continue without."""


def _pages(client, operation: str, **kwargs):
    """Yield pages whether or not botocore knows a paginator for the call."""
    if client.can_paginate(operation):
        yield from client.get_paginator(operation).paginate(**kwargs)
        return
    yield getattr(client, operation)(**kwargs)


def _group_from_api(raw: dict, region: str) -> ReplicationGroup:
    node_groups = []
    for ng in raw.get("NodeGroups", []) or []:
        members = []
        azs = []
        for m in ng.get("NodeGroupMembers", []) or []:
            cid = m.get("CacheClusterId", "")
            if cid:
                members.append(cid)
            az = m.get("PreferredAvailabilityZone", "")
            if az:
                azs.append(az)
        node_groups.append(
            NodeGroup(id=ng.get("NodeGroupId", ""), members=members, availability_zones=azs)
        )
    return ReplicationGroup(
        id=raw.get("ReplicationGroupId", ""),
        region=region,
        engine=(raw.get("Engine") or "redis").lower(),
        engine_version=raw.get("EngineVersion", ""),
        status=raw.get("Status", ""),
        automatic_failover=(raw.get("AutomaticFailover") or "disabled").lower(),
        multi_az=(raw.get("MultiAZ") or "disabled").lower(),
        transit_encryption=bool(raw.get("TransitEncryptionEnabled", False)),
        at_rest_encryption=bool(raw.get("AtRestEncryptionEnabled", False)),
        auth_token=bool(raw.get("AuthTokenEnabled", False)),
        snapshot_retention=int(raw.get("SnapshotRetentionLimit", 0) or 0),
        node_groups=node_groups,
        auto_minor_upgrade=raw.get("AutoMinorVersionUpgrade"),
    )


def _cluster_from_api(raw: dict, region: str) -> CacheCluster:
    azs = []
    preferred = raw.get("PreferredAvailabilityZone", "")
    if preferred and preferred != "Multiple":
        azs.append(preferred)
    for node in raw.get("CacheNodes", []) or []:
        az = node.get("CustomerAvailabilityZone", "")
        if az and az not in azs:
            azs.append(az)
    return CacheCluster(
        id=raw.get("CacheClusterId", ""),
        region=region,
        engine=(raw.get("Engine") or "").lower(),
        engine_version=raw.get("EngineVersion", ""),
        status=raw.get("CacheClusterStatus", ""),
        replication_group_id=raw.get("ReplicationGroupId", "") or "",
        num_nodes=int(raw.get("NumCacheNodes", 1) or 1),
        availability_zones=sorted(azs),
        snapshot_retention=int(raw.get("SnapshotRetentionLimit", 0) or 0),
        auto_minor_upgrade=bool(raw.get("AutoMinorVersionUpgrade", True)),
        transit_encryption=bool(raw.get("TransitEncryptionEnabled", False)),
        at_rest_encryption=bool(raw.get("AtRestEncryptionEnabled", False)),
        auth_token=bool(raw.get("AuthTokenEnabled", False)),
    )


def collect_region(client, region: str) -> Inventory:
    """Describe groups, clusters and supported engine versions in one region.

    A denial on DescribeReplicationGroups or DescribeCacheClusters raises
    CollectError: without them there is nothing to audit. A denial on
    DescribeCacheEngineVersions only drops the engine-version rule, so it is
    recorded as a warning and the scan continues.
    """
    inv = Inventory(region=region)

    try:
        for page in _pages(client, "describe_replication_groups"):
            for raw in page.get("ReplicationGroups", []) or []:
                inv.groups.append(_group_from_api(raw, region))
    except ClientError as exc:
        raise CollectError(f"{region}: DescribeReplicationGroups failed: {_msg(exc)}") from exc

    try:
        for page in _pages(client, "describe_cache_clusters", ShowCacheNodeInfo=True):
            for raw in page.get("CacheClusters", []) or []:
                inv.clusters.append(_cluster_from_api(raw, region))
    except ClientError as exc:
        raise CollectError(f"{region}: DescribeCacheClusters failed: {_msg(exc)}") from exc

    _enrich_groups(inv)

    try:
        versions: dict[str, list[str]] = {}
        for page in _pages(client, "describe_cache_engine_versions"):
            for raw in page.get("CacheEngineVersions", []) or []:
                engine = (raw.get("Engine") or "").lower()
                ver = raw.get("EngineVersion", "")
                if engine and ver:
                    versions.setdefault(engine, [])
                    if ver not in versions[engine]:
                        versions[engine].append(ver)
        inv.engine_versions = EngineVersions(by_engine=versions)
    except ClientError as exc:
        inv.engine_versions = None
        inv.warnings.append(
            f"{region}: DescribeCacheEngineVersions failed ({_msg(exc)}); "
            "skipping ENGINE_VERSION_UNSUPPORTED in this region"
        )

    return inv


def _enrich_groups(inv: Inventory) -> None:
    """Fill in what DescribeReplicationGroups does not return.

    The ReplicationGroup shape carries no EngineVersion -- the version lives on
    the member cache clusters -- so the group borrows it from its first member.
    Same for AutoMinorVersionUpgrade on older API versions, and for the
    availability zones when NodeGroupMembers came back without them.
    """
    by_id = {c.id: c for c in inv.clusters}
    for group in inv.groups:
        members = [by_id[m] for m in group.member_clusters if m in by_id]
        if not group.engine_version and members:
            group.engine_version = members[0].engine_version
        if not group.engine and members:
            group.engine = members[0].engine
        if group.auto_minor_upgrade is None and members:
            group.auto_minor_upgrade = all(m.auto_minor_upgrade for m in members)
        for node_group in group.node_groups:
            if node_group.availability_zones:
                continue
            node_group.availability_zones = [
                az
                for m in node_group.members
                if m in by_id
                for az in by_id[m].availability_zones
            ]


def _msg(exc: ClientError) -> str:
    err = exc.response.get("Error", {})
    code = err.get("Code", "ClientError")
    message = err.get("Message", str(exc))
    return f"{code}: {message}"


def enabled_regions(ec2_client) -> list[str]:
    try:
        resp = ec2_client.describe_regions()
    except ClientError as exc:
        raise CollectError(f"DescribeRegions failed: {_msg(exc)}") from exc
    return sorted(r["RegionName"] for r in resp.get("Regions", []) or [])
