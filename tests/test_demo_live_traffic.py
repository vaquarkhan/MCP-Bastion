"""Cover dashboard demo live traffic loop (short bounded run)."""

import random
import threading
import time

import pytest

from mcp_bastion.demo_live_traffic import live_simulator
from mcp_bastion.pillars.metrics import MetricsStore


@pytest.fixture(autouse=True)
def _reset_metrics():
    MetricsStore.get().reset()
    yield
    MetricsStore.get().reset()


def test_live_simulator_records_metrics():
    # First loop iteration always blocks on stop.wait(timeout). If we set stop during that wait,
    # wait() returns True and the loop exits without ever recording metrics — wait past one timeout.
    stop = threading.Event()
    rng = random.Random(42)
    t = threading.Thread(target=live_simulator, args=(stop, rng), daemon=True)
    t.start()
    time.sleep(1.25)
    stop.set()
    t.join(timeout=5.0)
    assert not t.is_alive()
    m = MetricsStore.get().get_metrics()
    total = int(m.get("requests_total", 0)) + int(m.get("blocked_total", 0))
    assert total > 0, "live_simulator should record at least one request or block"
