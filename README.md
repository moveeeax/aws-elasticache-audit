# aws-elasticache-audit

[![ci](https://github.com/moveeeax/aws-elasticache-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-elasticache-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Everybody calls ElastiCache a cache right up to the morning it holds the only copy of
every live session. A Redis replication group with `AutomaticFailover` disabled does not
promote a replica when the primary dies — it waits for a human. A group with one node in
one availability zone has no replica to promote at all. `TransitEncryptionEnabled`
defaults to off on older groups, so session tokens cross the VPC in plaintext.

`aws-elasticache-audit` reads every replication group and cache cluster once and says
which of them cannot survive losing a node.

## Rules

| Rule | Severity | Fires when |
| --- | --- | --- |
| `GROUP_SINGLE_NODE` | high | a node group has exactly one member cluster |
| `GROUP_NO_AUTOMATIC_FAILOVER` | high | `AutomaticFailover` is not `enabled` on a group that has a replica |
| `GROUP_NO_TRANSIT_ENCRYPTION` | high | `TransitEncryptionEnabled` is false |
| `ENGINE_VERSION_UNSUPPORTED` | high | the engine version is absent from `DescribeCacheEngineVersions` |
| `GROUP_NO_AUTH_TOKEN` | medium | `AuthTokenEnabled` is false on a Redis group |
| `GROUP_NO_AT_REST_ENCRYPTION` | medium | `AtRestEncryptionEnabled` is false |
| `NO_SNAPSHOT_RETENTION` | medium | `SnapshotRetentionLimit` is 0 on a Redis group or cluster |
| `NO_AUTO_MINOR_UPGRADE` | low | `AutoMinorVersionUpgrade` is false |
| `CLUSTER_ORPHAN_NODE` | low | a Redis cache cluster belongs to no replication group |

Failover on a group without a replica is a consequence of `GROUP_SINGLE_NODE`, not a
second fault, so a single-node group reports the missing replica and stays quiet about
failover.

## Install

```
pip install git+https://github.com/moveeeax/aws-elasticache-audit
```

Needs `elasticache:Describe*` and, for `--all-regions`, `ec2:DescribeRegions`.

## Usage

```
aws-elasticache-audit --region eu-central-1
aws-elasticache-audit --all-regions --format json --fail-on high
aws-elasticache-audit --group prod-sessions --ignore NO_AUTO_MINOR_UPGRADE
```

Real output, from the recorded fixture in `examples/fixtures/risky.json`:

```
$ python examples/offline_demo.py risky
eu-central-1
  HIGH   ENGINE_VERSION_UNSUPPORTED   legacy-cart (redis 5.0.6, 2 node(s))
         redis 5.0.6 is not in DescribeCacheEngineVersions; the oldest version AWS still
         supports for redis is 6.2. AWS forces the upgrade on its own schedule once
         support ends.
         fix: aws elasticache modify-replication-group --replication-group-id legacy-cart
         --engine-version 6.2 --apply-immediately

  HIGH   GROUP_SINGLE_NODE            prod-sessions-single (redis 7.1.0, 1 node(s))
         1 shard with a single member cluster (0001); the group has no replica to promote
         when the primary node fails. 1 availability zone (eu-central-1a).
         members: prod-sessions-single-001
         fix: aws elasticache increase-replica-count --replication-group-id
         prod-sessions-single --new-replica-count 1 --apply-immediately

  MEDIUM GROUP_NO_AT_REST_ENCRYPTION  prod-sessions-single (redis 7.1.0, 1 node(s))
         AtRestEncryptionEnabled is false; snapshots and the on-disk data land unencrypted.
         fix (not in place): cannot be changed in place on this group: restore a snapshot
         into a new group created with --at-rest-encryption-enabled

10 finding(s): 4 high, 4 medium, 2 low across 2 replication group(s) and 2 cache
cluster(s) in 1 region(s).
```

(trimmed to three findings; `fix (not in place)` marks the ones that need a restore into
a new group rather than a `modify-*` call)

### Flags

| Flag | Meaning |
| --- | --- |
| `--profile NAME` | AWS named profile |
| `--region REGION` | region to scan, repeatable |
| `--all-regions` | every region enabled for the account |
| `--group ID` | limit to a replication group id, repeatable |
| `--engine redis\|memcached` | limit to one engine |
| `--format table\|json\|csv` | output shape, default `table` |
| `--fail-on high\|medium\|low\|never` | lowest severity that makes the exit code 1, default `high` |
| `--ignore RULE,RULE` | drop rules from the output and the exit code |
| `--list-rules` | print the rules and exit |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | no finding at or above `--fail-on` |
| 1 | at least one finding at or above `--fail-on` |
| 2 | an AWS API, credential or argument error |

## How it works

One pass per region over three calls:

- `DescribeReplicationGroups` — failover, multi-AZ, both encryption flags, the auth
  token, snapshot retention and the node groups with their member clusters.
- `DescribeCacheClusters` with `ShowCacheNodeInfo` — the memcached clusters, the
  standalone Redis nodes that belong to no group, and the engine version. The
  `ReplicationGroup` shape carries no `EngineVersion` at all, so a group borrows the
  version from its first member cluster.
- `DescribeCacheEngineVersions` — the only authoritative list of what AWS still
  supports. A denial here drops just the engine-version rule, with a warning, and the
  rest of the scan stands.

Cluster-level rules only apply to clusters outside a replication group: every node of a
group is also a cache cluster, so judging members too would report the same fault once
per node.

Version comparison matches on the version line, not the string: AWS reports `7.1` as
supported while a group reports `7.1.0`, and an exact match would call every live group
end-of-support.

## In CI

```yaml
- name: ElastiCache audit
  run: aws-elasticache-audit --all-regions --fail-on high --format json
```

## Development

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The suite replays recorded fixtures through botocore's `Stubber`, which validates them
against the real service model — a fixture that drifts from the API fails the test
instead of passing quietly. No test touches AWS.

## License

MIT
