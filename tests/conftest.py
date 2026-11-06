"""Stubbed ElastiCache clients over the recorded fixtures in examples/fixtures.

Nothing in the suite touches AWS: botocore's Stubber replays the recorded
responses and validates them against the real service model, so a fixture that
drifts from the API shape fails the test instead of passing quietly.
"""

from __future__ import annotations

import json
from pathlib import Path

import boto3
import pytest
from botocore.stub import ANY, Stubber

FIXTURES = Path(__file__).resolve().parent.parent / "examples" / "fixtures"

CALLS = [
    ("describe_replication_groups", {}),
    ("describe_cache_clusters", {"ShowCacheNodeInfo": True}),
    ("describe_cache_engine_versions", {}),
]


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def stubbed_client(name: str, errors: dict[str, tuple[str, str]] | None = None):
    """Return (client, stubber, region) replaying the named fixture.

    errors maps an operation name to (code, message) to queue a ClientError in
    place of its recorded response.
    """
    fixture = load_fixture(name)
    region = fixture["region"]
    client = boto3.client(
        "elasticache",
        region_name=region,
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )
    stubber = Stubber(client)
    errors = errors or {}

    for operation, params in CALLS:
        if operation in errors:
            code, message = errors[operation]
            stubber.add_client_error(
                operation,
                service_error_code=code,
                service_message=message,
                http_status_code=400,
                expected_params=params,
            )
            continue
        for page in fixture[operation]:
            stubber.add_response(operation, page, params)

    stubber.activate()
    return client, stubber, region


class FakeSession:
    """Hands the CLI a pre-stubbed client instead of a real boto3 session."""

    def __init__(self, clients: dict[str, object], region_name: str = "eu-central-1"):
        self._clients = clients
        self.region_name = region_name

    def client(self, service: str, region_name: str | None = None, **_):
        key = f"{service}:{region_name}" if f"{service}:{region_name}" in self._clients else service
        return self._clients[key]


class FakeEc2:
    def __init__(self, regions: list[str]):
        self._regions = regions

    def describe_regions(self):
        return {"Regions": [{"RegionName": r} for r in self._regions]}


@pytest.fixture
def healthy():
    client, stubber, region = stubbed_client("healthy")
    yield client, region
    stubber.deactivate()


@pytest.fixture
def risky():
    client, stubber, region = stubbed_client("risky")
    yield client, region
    stubber.deactivate()


@pytest.fixture
def sharded():
    client, stubber, region = stubbed_client("sharded")
    yield client, region
    stubber.deactivate()


__all__ = [
    "ANY",
    "FakeEc2",
    "FakeSession",
    "load_fixture",
    "stubbed_client",
]
