"""Tests for metrics store and dashboard metrics."""

import time

import pytest

from mcp_bastion.pillars.metrics import (
    TIME_BUCKET_COUNT,
    TIME_BUCKET_SECONDS,
    DashboardMetrics,
    MetricsStore,
)


def test_dashboard_metrics_to_dict():
    m = DashboardMetrics(requests_total=10, blocked_total=2, cost_total=1.5)
    d = m.to_dict()
    assert d["requests_total"] == 10
    assert d["blocked_total"] == 2
    assert d["blocked_pct"] == 20.0
    assert d["cost_total"] == 1.5
    assert "blocked_by_reason" in d
    assert "blocked_by_kind" in d
    assert "top_tools" in d
    assert "alerts" in d
    assert "window_start" in d
    assert "pii_by_entity" in d


def test_dashboard_metrics_zero_requests_no_divide_by_zero():
    m = DashboardMetrics(requests_total=0, blocked_total=0)
    d = m.to_dict()
    assert d["blocked_pct"] == 0.0


def test_metrics_store_get_singleton():
    a = MetricsStore.get()
    b = MetricsStore.get()
    assert a is b


def test_metrics_store_record_request():
    store = MetricsStore.get()
    store.reset()
    store.record_request("add", "user1")
    store.record_request("add", "user1")
    store.record_request("get_weather", None)
    m = store.get_metrics()
    assert m["requests_total"] == 3
    assert m["top_tools"]["add"] == 2
    assert m["top_tools"]["get_weather"] == 1


def test_metrics_store_record_blocked():
    store = MetricsStore.get()
    store.reset()
    store.record_blocked("rate limit", "add")
    store.record_blocked("rate limit", "add")
    store.record_blocked("injection", "run")
    m = store.get_metrics()
    assert m["blocked_total"] == 3
    assert m["blocked_by_reason"]["rate limit"] == 2
    assert m["blocked_by_reason"]["injection"] == 1
    assert m["blocked_by_kind"]["rate_limit"] == 2
    assert m["blocked_by_kind"]["injection"] == 1


def test_metrics_store_record_pii_redacted():
    store = MetricsStore.get()
    store.reset()
    store.record_pii_redacted(1)
    store.record_pii_redacted(3)
    m = store.get_metrics()
    assert m["pii_redacted_total"] == 4


def test_metrics_store_record_cost():
    store = MetricsStore.get()
    store.reset()
    store.record_cost(0.5, "user1")
    store.record_cost(0.3, "user1")
    store.record_cost(0.2, "user2")
    m = store.get_metrics()
    assert m["cost_total"] == 1.0
    assert m["cost_by_user"]["user1"] == 0.8
    assert m["cost_by_user"]["user2"] == 0.2


def test_metrics_store_add_alert():
    store = MetricsStore.get()
    store.reset()
    store.add_alert("injection", "Blocked", "warning")
    store.add_alert("rate_limit", "Limit exceeded", "critical")
    m = store.get_metrics()
    assert len(m["alerts"]) == 2
    assert m["alerts"][0]["kind"] == "injection"
    assert m["alerts"][1]["severity"] == "critical"


def test_metrics_store_reset():
    store = MetricsStore.get()
    store.record_request("add", "u1")
    store.reset()
    m = store.get_metrics()
    assert m["requests_total"] == 0
    assert m["top_tools"] == {}


def test_metrics_store_add_alert_truncates_at_100():
    store = MetricsStore.get()
    store.reset()
    for i in range(105):
        store.add_alert("k", f"msg{i}")
    m = store.get_metrics()
    assert len(m["alerts"]) == 10
    assert m["alerts"][0]["message"] == "msg95"


def test_metrics_store_time_series_shape():
    store = MetricsStore.get()
    store.reset()
    store.record_request("a", None)
    store.record_blocked("x", "b")
    m = store.get_metrics()
    assert m["time_series_bucket_seconds"] == TIME_BUCKET_SECONDS
    assert m["time_series_window_seconds"] == TIME_BUCKET_SECONDS * TIME_BUCKET_COUNT
    assert len(m["time_series"]) == TIME_BUCKET_COUNT
    total_allowed = sum(b["allowed"] for b in m["time_series"])
    total_blocked = sum(b["blocked"] for b in m["time_series"])
    assert total_allowed == 1
    assert total_blocked == 1


def test_metrics_store_reset_clears_time_series():
    store = MetricsStore.get()
    store.record_request("t", None)
    store.reset()
    m = store.get_metrics()
    assert sum(b["allowed"] + b["blocked"] for b in m["time_series"]) == 0


def test_bump_time_bucket_noop_when_zero():
    store = MetricsStore.get()
    store.reset()
    store._bump_time_bucket()
    assert store._time_buckets == {}


def test_metrics_store_prunes_stale_time_buckets():
    store = MetricsStore.get()
    store.reset()
    bid_now = store._bucket_id(time.time())
    stale = bid_now - TIME_BUCKET_COUNT - 3
    store._time_buckets[stale] = [9, 9]
    store.record_request("x", None)
    assert stale not in store._time_buckets


def test_metrics_store_latency_percentiles():
    store = MetricsStore.get()
    store.reset()
    for ms in [1.0, 2.0, 3.0, 4.0, 100.0]:
        store.record_latency_ms(ms)
    m = store.get_metrics()
    lat = m["latency_ms"]
    assert lat["samples"] == 5
    assert lat["p50"] >= 1.0
    assert lat["p99"] >= lat["p95"] >= lat["p50"]


def test_metrics_store_pii_entities():
    store = MetricsStore.get()
    store.reset()
    store.record_pii_entities({"EMAIL_ADDRESS": 2, "PERSON": 1})
    m = store.get_metrics()
    assert m["pii_redacted_total"] == 3
    assert m["pii_by_entity"]["EMAIL_ADDRESS"] == 2
    assert m["pii_by_entity"]["PERSON"] == 1


def test_metrics_store_cost_burn_fields():
    store = MetricsStore.get()
    store.reset()
    store.record_cost(1.0, "u1")
    m = store.get_metrics()
    assert "per_hour_usd" in m["cost_burn"]
    assert "projected_daily_usd" in m["cost_burn"]
    assert m["cost_burn"]["window_elapsed_seconds"] >= 1.0


def test_metrics_store_record_pii_entities_empty():
    store = MetricsStore.get()
    store.reset()
    store.record_pii_entities({})
    assert store.get_metrics()["pii_redacted_total"] == 0


def test_metrics_store_record_pii_entities_skips_nonpositive():
    store = MetricsStore.get()
    store.reset()
    store.record_pii_entities({"A": 0, "B": -2})
    assert store.get_metrics()["pii_redacted_total"] == 0


def test_metrics_store_record_latency_bounds():
    store = MetricsStore.get()
    store.reset()
    store.record_latency_ms(-5)
    store.record_latency_ms(9999999)
    assert store.get_metrics()["latency_ms"]["samples"] == 0


def test_metrics_store_latency_single_sample_percentile():
    store = MetricsStore.get()
    store.reset()
    store.record_latency_ms(99.5)
    m = store.get_metrics()
    assert m["latency_ms"]["p50"] == 99.5
    assert m["latency_ms"]["p99"] == 99.5


def test_metrics_store_tool_stats_and_pillar_health():
    store = MetricsStore.get()
    store.reset()
    store.record_request("search", "u1")
    store.record_latency_ms(12.0)
    store.record_tool_latency_ms("search", 12.0)
    store.record_blocked("Rate limit exceeded", "search")
    store.record_tool_latency_ms("search", 30.0)
    store.record_pii_entities({"EMAIL_ADDRESS": 1})
    m = store.get_metrics()

    assert "tool_stats" in m
    assert "search" in m["tool_stats"]
    ts = m["tool_stats"]["search"]
    assert ts["total"] == 2
    assert ts["blocked"] == 1
    assert ts["latency_samples"] == 2
    assert ts["blocked_reasons"]["rate_limit"] == 1

    pillars = {p["name"]: p for p in m["pillar_health"]}
    assert pillars["Rate Limiter"]["status"] == "active"
    assert pillars["PII Redaction"]["status"] == "active"


def test_metrics_elapsed_window_bad_iso():
    assert MetricsStore._elapsed_seconds_window("invalid") == 1.0
