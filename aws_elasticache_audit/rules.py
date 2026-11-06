"""The audit rules.

Pure functions over the shapes in model.py: no AWS client reaches this module,
which is why the tests can cover every rule without a credential.
"""

from __future__ import annotations

from .model import CacheCluster, EngineVersions, Finding, Inventory, ReplicationGroup

RULES: dict[str, str] = {
    "GROUP_NO_AUTOMATIC_FAILOVER": "high",
    "GROUP_SINGLE_NODE": "high",
    "GROUP_NO_TRANSIT_ENCRYPTION": "high",
    "ENGINE_VERSION_UNSUPPORTED": "high",
    "GROUP_NO_AUTH_TOKEN": "medium",
    "GROUP_NO_AT_REST_ENCRYPTION": "medium",
    "NO_SNAPSHOT_RETENTION": "medium",
    "NO_AUTO_MINOR_UPGRADE": "low",
    "CLUSTER_ORPHAN_NODE": "low",
}


def version_key(version: str) -> tuple[int, ...]:
    parts = []
    for chunk in version.split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _same_line(a: str, b: str) -> bool:
    """True when two versions agree on every component both of them state.

    DescribeCacheEngineVersions reports redis 7.1 while a replication group
    reports 7.1.0, so an exact string match would call every live group
    unsupported. A dotted-prefix match on either side is the honest comparison.
    """
    left, right = a.split("."), b.split(".")
    if not left or not right:
        return False
    width = min(len(left), len(right))
    return left[:width] == right[:width]


def is_supported(engine: str, version: str, versions: EngineVersions) -> bool:
    supported = versions.supported(engine)
    if not supported or not version:
        return True
    return any(_same_line(version, s) for s in supported)


def oldest_supported(engine: str, versions: EngineVersions) -> str:
    supported = versions.supported(engine)
    if not supported:
        return ""
    return sorted(supported, key=version_key)[0]


def _az_phrase(azs: list[str]) -> str:
    if not azs:
        return "no availability zone reported"
    noun = "zone" if len(azs) == 1 else "zones"
    return f"{len(azs)} availability {noun} ({', '.join(azs)})"


def _group_finding(group: ReplicationGroup, rule: str, detail: str, remediation: str,
                   in_place: bool = True, members: list[str] | None = None) -> Finding:
    return Finding(
        rule=rule,
        severity=RULES[rule],
        region=group.region,
        resource_type="replication-group",
        resource_id=group.id,
        engine=group.engine,
        engine_version=group.engine_version,
        node_count=group.node_count,
        availability_zones=group.availability_zones,
        detail=detail,
        remediation=remediation,
        in_place=in_place,
        members=members or [],
    )


def _cluster_finding(cluster: CacheCluster, rule: str, detail: str, remediation: str,
                     in_place: bool = True) -> Finding:
    return Finding(
        rule=rule,
        severity=RULES[rule],
        region=cluster.region,
        resource_type="cache-cluster",
        resource_id=cluster.id,
        engine=cluster.engine,
        engine_version=cluster.engine_version,
        node_count=cluster.num_nodes,
        availability_zones=cluster.availability_zones,
        detail=detail,
        remediation=remediation,
        in_place=in_place,
    )


def evaluate_group(group: ReplicationGroup, versions: EngineVersions | None) -> list[Finding]:
    out: list[Finding] = []
    single = group.single_node_shards

    if single:
        shard_ids = [ng.id or "(unnamed)" for ng in single]
        plural = "shard" if len(single) == 1 else "shards"
        out.append(
            _group_finding(
                group,
                "GROUP_SINGLE_NODE",
                f"{len(single)} {plural} with a single member cluster "
                f"({', '.join(shard_ids)}); the group has no replica to promote when the "
                f"primary node fails. {_az_phrase(group.availability_zones).capitalize()}.",
                f"aws elasticache increase-replica-count --replication-group-id {group.id} "
                "--new-replica-count 1 --apply-immediately",
                members=[m for ng in single for m in ng.members],
            )
        )

    # Failover on a group that has no replica is a consequence of GROUP_SINGLE_NODE,
    # not a second fault, so it is only reported where a replica exists to promote.
    if group.has_any_replica and group.automatic_failover != "enabled":
        out.append(
            _group_finding(
                group,
                "GROUP_NO_AUTOMATIC_FAILOVER",
                f"AutomaticFailover is {group.automatic_failover} on a group that has a "
                f"replica, so a primary node failure waits for a human. MultiAZ is "
                f"{group.multi_az}.",
                f"aws elasticache modify-replication-group --replication-group-id {group.id} "
                "--automatic-failover-enabled --multi-az-enabled --apply-immediately",
            )
        )

    if not group.transit_encryption:
        out.append(
            _group_finding(
                group,
                "GROUP_NO_TRANSIT_ENCRYPTION",
                "TransitEncryptionEnabled is false; client traffic, including any auth "
                "token, crosses the VPC in plaintext.",
                "cannot be changed in place on this group: snapshot it "
                f"(aws elasticache create-snapshot --replication-group-id {group.id} "
                f"--snapshot-name {group.id}-tls) and restore into a new group created with "
                "--transit-encryption-enabled",
                in_place=False,
            )
        )

    if group.engine == "redis" and not group.auth_token:
        out.append(
            _group_finding(
                group,
                "GROUP_NO_AUTH_TOKEN",
                "AuthTokenEnabled is false; anything that can reach the port speaks Redis "
                "to this group.",
                f"aws elasticache modify-replication-group --replication-group-id {group.id} "
                "--auth-token <token> --auth-token-update-strategy SET --apply-immediately "
                "(requires transit encryption)",
            )
        )

    if not group.at_rest_encryption:
        out.append(
            _group_finding(
                group,
                "GROUP_NO_AT_REST_ENCRYPTION",
                "AtRestEncryptionEnabled is false; snapshots and the on-disk data land "
                "unencrypted.",
                "cannot be changed in place on this group: restore a snapshot into a new "
                "group created with --at-rest-encryption-enabled",
                in_place=False,
            )
        )

    if group.engine == "redis" and group.snapshot_retention == 0:
        out.append(
            _group_finding(
                group,
                "NO_SNAPSHOT_RETENTION",
                "SnapshotRetentionLimit is 0, so no automatic backup exists to restore from.",
                f"aws elasticache modify-replication-group --replication-group-id {group.id} "
                "--snapshot-retention-limit 7 --apply-immediately",
            )
        )

    if group.auto_minor_upgrade is False:
        out.append(
            _group_finding(
                group,
                "NO_AUTO_MINOR_UPGRADE",
                "AutoMinorVersionUpgrade is false; patch releases land only when somebody "
                "schedules them.",
                f"aws elasticache modify-replication-group --replication-group-id {group.id} "
                "--auto-minor-version-upgrade --apply-immediately",
            )
        )

    out.extend(_engine_version_findings(group, versions, _group_finding))
    return out


def evaluate_cluster(cluster: CacheCluster, versions: EngineVersions | None) -> list[Finding]:
    """Rules for clusters that belong to no replication group.

    Every node of a replication group is also a cache cluster, so applying these
    to members would report the same fault once per node.
    """
    if not cluster.standalone:
        return []

    out: list[Finding] = []

    if cluster.engine == "redis":
        out.append(
            _cluster_finding(
                cluster,
                "CLUSTER_ORPHAN_NODE",
                "A Redis cache cluster that belongs to no replication group: no replica, "
                "no failover and no promotion path. "
                f"{_az_phrase(cluster.availability_zones).capitalize()}.",
                f"aws elasticache create-replication-group --replication-group-id {cluster.id}-rg "
                f"--primary-cluster-id {cluster.id} --replication-group-description "
                "'adopted standalone node' --automatic-failover-enabled",
            )
        )
        if cluster.snapshot_retention == 0:
            out.append(
                _cluster_finding(
                    cluster,
                    "NO_SNAPSHOT_RETENTION",
                    "SnapshotRetentionLimit is 0, so no automatic backup exists to restore from.",
                    f"aws elasticache modify-cache-cluster --cache-cluster-id {cluster.id} "
                    "--snapshot-retention-limit 7 --apply-immediately",
                )
            )

    if not cluster.auto_minor_upgrade:
        out.append(
            _cluster_finding(
                cluster,
                "NO_AUTO_MINOR_UPGRADE",
                "AutoMinorVersionUpgrade is false; patch releases land only when somebody "
                "schedules them.",
                f"aws elasticache modify-cache-cluster --cache-cluster-id {cluster.id} "
                "--auto-minor-version-upgrade --apply-immediately",
            )
        )

    out.extend(_engine_version_findings(cluster, versions, _cluster_finding))
    return out


def _engine_version_findings(resource, versions: EngineVersions | None, make) -> list[Finding]:
    if versions is None:
        return []
    if is_supported(resource.engine, resource.engine_version, versions):
        return []
    target = oldest_supported(resource.engine, versions)
    target_phrase = (
        f"the oldest version AWS still supports for {resource.engine} is {target}"
        if target
        else f"AWS reports no supported version for {resource.engine}"
    )
    upgrade = (
        f"--engine-version {target}" if target else "--engine-version <supported version>"
    )
    noun = (
        f"--replication-group-id {resource.id}"
        if isinstance(resource, ReplicationGroup)
        else f"--cache-cluster-id {resource.id}"
    )
    verb = (
        "modify-replication-group"
        if isinstance(resource, ReplicationGroup)
        else "modify-cache-cluster"
    )
    return [
        make(
            resource,
            "ENGINE_VERSION_UNSUPPORTED",
            f"{resource.engine} {resource.engine_version} is not in "
            f"DescribeCacheEngineVersions; {target_phrase}. AWS forces the upgrade on its "
            "own schedule once support ends.",
            f"aws elasticache {verb} {noun} {upgrade} --apply-immediately",
        )
    ]


def evaluate(inv: Inventory) -> list[Finding]:
    out: list[Finding] = []
    for group in inv.groups:
        out.extend(evaluate_group(group, inv.engine_versions))
    for cluster in inv.clusters:
        out.extend(evaluate_cluster(cluster, inv.engine_versions))
    return out
