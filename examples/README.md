# examples

Recorded `DescribeReplicationGroups` / `DescribeCacheClusters` /
`DescribeCacheEngineVersions` responses, used both by the test suite and by
`offline_demo.py`. They are shaped exactly like the real API, so botocore's `Stubber`
validates them.

| Fixture | What it holds |
| --- | --- |
| `fixtures/healthy.json` | one multi-AZ Redis group: failover on, both encryption flags, an auth token, seven days of snapshots, a supported engine. Zero findings, exit 0. |
| `fixtures/risky.json` | a single-node group with everything off, a group pinned to Redis 5.0.6, a memcached cluster, a standalone Redis node. Ten findings, exit 1. |
| `fixtures/sharded.json` | a cluster-mode group with three shards and no replica in any of them: one `GROUP_SINGLE_NODE` finding listing three members. |

Run the audit against one of them without an AWS account:

```
python examples/offline_demo.py            # risky, table
python examples/offline_demo.py healthy    # clean region
python examples/offline_demo.py risky json # machine-readable
```

The exit code is the one the real CLI would return.
