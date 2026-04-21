"""Tests for governance registry beacon."""

from unittest import mock

import pytest

from mcp_bastion.governance_beacon import (
    reset_registry_beacon_for_tests,
    schedule_registry_beacon,
    send_registry_beacon,
)


@pytest.fixture(autouse=True)
def _reset_beacon():
    reset_registry_beacon_for_tests()
    yield
    reset_registry_beacon_for_tests()


def test_send_registry_beacon_dedupes_same_url():
    calls: list[int] = []

    class Resp:
        status = 200

        def read(self, n: int = -1) -> bytes:
            calls.append(1)
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with mock.patch("mcp_bastion.governance_beacon.urllib.request.urlopen", return_value=Resp()) as op:
        send_registry_beacon("http://example.test/beacon", {"a": 1})
        send_registry_beacon("http://example.test/beacon", {"a": 2})
    assert op.call_count == 1


def test_send_registry_beacon_urlerror_logged():
    import urllib.error

    reset_registry_beacon_for_tests()
    with mock.patch(
        "mcp_bastion.governance_beacon.urllib.request.urlopen",
        side_effect=urllib.error.URLError("x"),
    ):
        send_registry_beacon("http://example.test/beacon2", {"x": 1})


def test_schedule_registry_beacon_no_url():
    schedule_registry_beacon(None, {})


def test_send_registry_beacon_generic_exception_logged():
    reset_registry_beacon_for_tests()
    with mock.patch(
        "mcp_bastion.governance_beacon.urllib.request.urlopen",
        side_effect=RuntimeError("boom"),
    ):
        send_registry_beacon("http://example.test/beacon-generic", {"a": 1})


def test_schedule_registry_beacon_starts_thread():
    reset_registry_beacon_for_tests()

    class Resp:
        status = 200

        def read(self, n: int = -1) -> bytes:
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with mock.patch("mcp_bastion.governance_beacon.urllib.request.urlopen", return_value=Resp()):
        schedule_registry_beacon("http://example.test/beacon3", {"event": "t"})
    # thread may still be running briefly; no assertion on network
