#!/usr/bin/env python3
"""Run the audit against a recorded fixture, with no AWS account involved.

    python examples/offline_demo.py                 # the risky region
    python examples/offline_demo.py healthy         # the clean region
    python examples/offline_demo.py risky json      # machine-readable

Exit code is the real one the CLI would return.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import boto3
from botocore.stub import Stubber

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aws_elasticache_audit.cli import main  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CALLS = [
    ("describe_replication_groups", {}),
    ("describe_cache_clusters", {"ShowCacheNodeInfo": True}),
    ("describe_cache_engine_versions", {}),
]


class SingleRegionSession:
    def __init__(self, client, region: str):
        self._client = client
        self.region_name = region

    def client(self, service, region_name=None, **_):
        if service != "elasticache":
            raise RuntimeError(f"the demo only stubs elasticache, not {service}")
        return self._client


def main_demo(argv: list[str]) -> int:
    name = argv[0] if argv else "risky"
    fmt = argv[1] if len(argv) > 1 else "table"
    fixture = json.loads((FIXTURES / f"{name}.json").read_text())
    region = fixture["region"]

    client = boto3.client(
        "elasticache",
        region_name=region,
        aws_access_key_id="demo",
        aws_secret_access_key="demo",
    )
    stubber = Stubber(client)
    for operation, params in CALLS:
        for page in fixture[operation]:
            stubber.add_response(operation, page, params)
    stubber.activate()

    return main(
        ["--region", region, "--format", fmt],
        session=SingleRegionSession(client, region),
    )


if __name__ == "__main__":
    raise SystemExit(main_demo(sys.argv[1:]))
