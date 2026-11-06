"""Data shapes shared by the collector, the rules and the reporters."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


def severity_rank(name: str) -> int:
    return SEVERITY_ORDER[name]


@dataclass
class NodeGroup:
    """One shard of a replication group."""

    id: str
    members: list[str] = field(default_factory=list)
    availability_zones: list[str] = field(default_factory=list)

    @property
    def has_replica(self) -> bool:
        return len(self.members) > 1


@dataclass
class ReplicationGroup:
    id: str
    region: str
    engine: str
    engine_version: str
    status: str = ""
    automatic_failover: str = "disabled"
    multi_az: str = "disabled"
    transit_encryption: bool = False
    at_rest_encryption: bool = False
    auth_token: bool = False
    snapshot_retention: int = 0
    node_groups: list[NodeGroup] = field(default_factory=list)
    auto_minor_upgrade: bool | None = None

    @property
    def node_count(self) -> int:
        return sum(len(ng.members) for ng in self.node_groups)

    @property
    def availability_zones(self) -> list[str]:
        seen: list[str] = []
        for ng in self.node_groups:
            for az in ng.availability_zones:
                if az and az not in seen:
                    seen.append(az)
        return sorted(seen)

    @property
    def single_node_shards(self) -> list[NodeGroup]:
        return [ng for ng in self.node_groups if len(ng.members) == 1]

    @property
    def has_any_replica(self) -> bool:
        return any(ng.has_replica for ng in self.node_groups)

    @property
    def member_clusters(self) -> list[str]:
        out: list[str] = []
        for ng in self.node_groups:
            out.extend(ng.members)
        return out


@dataclass
class CacheCluster:
    id: str
    region: str
    engine: str
    engine_version: str
    status: str = ""
    replication_group_id: str = ""
    num_nodes: int = 1
    availability_zones: list[str] = field(default_factory=list)
    snapshot_retention: int = 0
    auto_minor_upgrade: bool = True
    transit_encryption: bool = False
    at_rest_encryption: bool = False
    auth_token: bool = False

    @property
    def standalone(self) -> bool:
        return not self.replication_group_id


@dataclass
class EngineVersions:
    """Supported versions per engine, as reported by DescribeCacheEngineVersions."""

    by_engine: dict[str, list[str]] = field(default_factory=dict)

    def supported(self, engine: str) -> list[str]:
        return self.by_engine.get(engine.lower(), [])


@dataclass
class Inventory:
    region: str
    groups: list[ReplicationGroup] = field(default_factory=list)
    clusters: list[CacheCluster] = field(default_factory=list)
    engine_versions: EngineVersions | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class Finding:
    rule: str
    severity: str
    region: str
    resource_type: str
    resource_id: str
    engine: str
    engine_version: str
    node_count: int
    availability_zones: list[str]
    detail: str
    remediation: str
    in_place: bool = True
    members: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "region": self.region,
            "resourceType": self.resource_type,
            "resourceId": self.resource_id,
            "engine": self.engine,
            "engineVersion": self.engine_version,
            "nodeCount": self.node_count,
            "availabilityZones": self.availability_zones,
            "members": self.members,
            "detail": self.detail,
            "remediation": self.remediation,
            "inPlace": self.in_place,
        }
