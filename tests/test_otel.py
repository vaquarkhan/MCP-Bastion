"""Tests for OpenTelemetry integration."""

import os
from unittest import mock

import pytest

from mcp_bastion import otel


@pytest.fixture(autouse=True)
def _reset_otel_module_state():
    otel._tracer = None
    otel._meter = None
    otel._cw_client = None
    otel._observability_target = None
    otel._otel_init_attempted = False
    yield
    otel._tracer = None
    otel._meter = None
    otel._cw_client = None
    otel._observability_target = None
    otel._otel_init_attempted = False


def test_get_tracer_without_endpoint_returns_none(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    otel._tracer = None
    otel._meter = None
    otel._otel_init_attempted = False
    tr = otel.get_tracer()
    assert tr is None


def test_get_tracer_returns_cached_when_already_set():
    """Cover _init_otel early return when _tracer is already set."""
    sentinel = object()
    otel._tracer = sentinel
    otel._meter = None
    otel._otel_init_attempted = False
    try:
        assert otel.get_tracer() is sentinel
    finally:
        otel._tracer = None
        otel._meter = None
        otel._otel_init_attempted = False


def test_init_otel_negative_cache_skips_repeated_datadog_probe(monkeypatch):
    """Without OTLP env, Datadog port probe must not run on every audit span."""
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("GRAFANA_CLOUD_OTLP_ENDPOINT", raising=False)
    otel._tracer = None
    otel._meter = None
    otel._cw_client = None
    otel._otel_init_attempted = False
    probe = mock.Mock(return_value=False)
    with mock.patch.object(otel, "_is_port_open", probe):
        otel.record_tool_span("add", "ALLOWED", 1.0, None)
        otel.record_tool_span("add", "ALLOWED", 2.0, None)
        otel.record_tool_span("run", "BLOCKED", 3.0, "rate_limit")
    assert probe.call_count == 1


def test_record_tool_span_no_tracer_is_noop(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    otel._tracer = None
    otel._meter = None
    otel._otel_init_attempted = False
    otel.record_tool_span("add", "ALLOWED", 10.5, None)
    otel.record_tool_span("run", "BLOCKED", 2.0, "injection")
    # No exception; no-op when tracer is None


def test_get_meter_returns_none_without_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    otel._tracer = None
    otel._meter = None
    assert otel.get_meter() is None


def test_record_tool_span_with_mock_tracer():
    otel._tracer = None
    otel._meter = None
    span = mock.MagicMock()
    ctx = mock.MagicMock()
    ctx.__enter__ = mock.MagicMock(return_value=span)
    ctx.__exit__ = mock.MagicMock(return_value=False)
    tracer = mock.MagicMock()
    tracer.start_as_current_span = mock.MagicMock(return_value=ctx)
    with mock.patch.object(otel, "get_tracer", return_value=tracer):
        otel.record_tool_span("add", "ALLOWED", 5.0, None)
    span.set_attribute.assert_called()
    assert span.set_status.call_count == 0


def test_record_tool_span_with_mock_tracer_and_error():
    otel._tracer = None
    otel._meter = None
    span = mock.MagicMock()
    ctx = mock.MagicMock()
    ctx.__enter__ = mock.MagicMock(return_value=span)
    ctx.__exit__ = mock.MagicMock(return_value=False)
    tracer = mock.MagicMock()
    tracer.start_as_current_span = mock.MagicMock(return_value=ctx)
    trace_module = mock.MagicMock()
    trace_module.Status = mock.MagicMock(return_value=mock.MagicMock())
    trace_module.StatusCode = mock.MagicMock(ERROR="ERROR")
    with mock.patch.object(otel, "get_tracer", return_value=tracer), \
         mock.patch.dict("sys.modules", {"opentelemetry.trace": trace_module}):
        otel.record_tool_span("add", "BLOCKED", 1.0, "injection")
    assert span.set_attribute.called
    calls = [str(c) for c in span.set_attribute.call_args_list]
    assert any("mcp.error" in c or "error" in c for c in calls)
    span.set_status.assert_called_once()


def test_record_tool_span_tracer_raises(caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    otel._tracer = None
    otel._meter = None
    tracer = mock.MagicMock()
    tracer.start_as_current_span = mock.MagicMock(side_effect=RuntimeError("otel error"))
    with mock.patch.object(otel, "get_tracer", return_value=tracer):
        otel.record_tool_span("add", "ALLOWED", 1.0, None)
    assert "otel" in caplog.text.lower() or "span" in caplog.text.lower() or "error" in caplog.text.lower()


def test_init_otel_endpoint_set_but_import_error(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    otel._tracer = None
    otel._meter = None
    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "opentelemetry":
            raise ImportError("No module named 'opentelemetry'")
        return real_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=fake_import):
        tr = otel.get_tracer()
    assert tr is None


def test_init_otel_otlp_import_fallback(monkeypatch):
    """Cover branch when opentelemetry is installed but OTLP grpc/http exporters fail."""
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    otel._tracer = None
    otel._meter = None
    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "opentelemetry":
            return real_import(name, *args, **kwargs)
        if "otlp" in name.lower() and "trace_exporter" in name.lower():
            raise ImportError("No OTLP exporter")
        return real_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=fake_import):
        tr = otel.get_tracer()
    assert tr is None


def test_init_otel_full_init_when_otel_installed(monkeypatch):
    """When opentelemetry and OTLP exporter are installed, full init runs (covers 42-47)."""
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    except ImportError:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        except ImportError:
            pytest.skip("opentelemetry OTLP exporter not installed")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    otel._tracer = None
    otel._meter = None
    try:
        tr = otel.get_tracer()
        assert tr is not None
    finally:
        otel._tracer = None
        otel._meter = None


def test_init_otel_full_init_with_mocked_otel(monkeypatch):
    """Cover full init path (30-49) by mocking opentelemetry modules."""
    import builtins
    real_import = builtins.__import__

    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    otel._tracer = None
    otel._meter = None

    mock_tracer = mock.MagicMock()
    mock_trace = mock.MagicMock()
    mock_trace.set_tracer_provider = mock.MagicMock()
    mock_trace.get_tracer = mock.MagicMock(return_value=mock_tracer)
    mock_metrics = mock.MagicMock()

    mock_otel = mock.MagicMock()
    mock_otel.trace = mock_trace
    mock_otel.metrics = mock_metrics

    mock_resource_cls = mock.MagicMock()
    mock_resource_cls.create = mock.MagicMock(return_value={})
    mock_tracer_provider = mock.MagicMock()
    mock_batch_processor_cls = mock.MagicMock(return_value=mock.MagicMock())
    mock_otlp_exporter = mock.MagicMock()

    sdk_trace_export = mock.MagicMock()
    sdk_trace_export.BatchSpanProcessor = mock_batch_processor_cls
    sdk_trace = mock.MagicMock()
    sdk_trace.TracerProvider = lambda **kw: mock_tracer_provider
    sdk_trace.export = sdk_trace_export

    sdk_resources = mock.MagicMock()
    sdk_resources.Resource = mock_resource_cls

    def fake_import(name, *args, **kwargs):
        if name == "opentelemetry":
            return mock_otel
        if name == "opentelemetry.sdk.trace":
            return sdk_trace
        if name == "opentelemetry.sdk.trace.export":
            return sdk_trace_export
        if name == "opentelemetry.sdk.resources":
            return sdk_resources
        if "otlp" in name.lower() and "trace_exporter" in name.lower():
            m = mock.MagicMock()
            m.OTLPSpanExporter = lambda endpoint: mock_otlp_exporter
            return m
        return real_import(name, *args, **kwargs)

    try:
        with mock.patch("builtins.__import__", side_effect=fake_import):
            tr = otel.get_tracer()
        assert tr is mock_tracer
        mock_trace.set_tracer_provider.assert_called_once()
        mock_trace.get_tracer.assert_called_once_with("mcp-bastion", "1.0.0")
    finally:
        otel._tracer = None
        otel._meter = None


def test_init_otel_otlp_grpc_fails_http_succeeds(monkeypatch):
    """Cover OTLP grpc import fail then http import succeed (lines 38-43)."""
    import builtins
    real_import = builtins.__import__

    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    otel._tracer = None
    otel._meter = None

    mock_tracer = mock.MagicMock()
    mock_trace = mock.MagicMock()
    mock_trace.set_tracer_provider = mock.MagicMock()
    mock_trace.get_tracer = mock.MagicMock(return_value=mock_tracer)
    mock_otel = mock.MagicMock()
    mock_otel.trace = mock_trace
    mock_otel.metrics = mock.MagicMock()

    sdk_trace_export = mock.MagicMock()
    sdk_trace_export.BatchSpanProcessor = mock.MagicMock(return_value=mock.MagicMock())
    sdk_trace = mock.MagicMock()
    sdk_trace.TracerProvider = lambda **kw: mock.MagicMock()
    sdk_trace.export = sdk_trace_export
    sdk_resources = mock.MagicMock()
    sdk_resources.Resource = mock.MagicMock(create=mock.MagicMock(return_value={}))
    mock_otlp = mock.MagicMock()
    mock_otlp.OTLPSpanExporter = lambda endpoint: mock.MagicMock()

    def fake_import(name, *args, **kwargs):
        if name == "opentelemetry":
            return mock_otel
        if name == "opentelemetry.sdk.trace":
            return sdk_trace
        if name == "opentelemetry.sdk.trace.export":
            return sdk_trace_export
        if name == "opentelemetry.sdk.resources":
            return sdk_resources
        if "grpc" in name and "trace_exporter" in name:
            raise ImportError("No grpc exporter")
        if "otlp" in name.lower() and "trace_exporter" in name.lower():
            return mock_otlp
        return real_import(name, *args, **kwargs)

    try:
        with mock.patch("builtins.__import__", side_effect=fake_import):
            tr = otel.get_tracer()
        assert tr is mock_tracer
    finally:
        otel._tracer = None
        otel._meter = None


def test_init_otel_otlp_both_grpc_and_http_fail(monkeypatch):
    """Cover inner except when http OTLP import also fails (lines 41-43)."""
    import builtins
    import importlib
    real_import = builtins.__import__
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

    def fake_import(name, *args, **kwargs):
        if name == "opentelemetry":
            return real_import(name, *args, **kwargs)
        if "otlp" in name.lower() and "trace_exporter" in name.lower():
            raise ImportError("No OTLP exporter")
        return real_import(name, *args, **kwargs)

    otel._tracer = None
    otel._meter = None
    with mock.patch("builtins.__import__", side_effect=fake_import):
        tr = otel.get_tracer()
    assert tr is None
    otel._tracer = None
    otel._meter = None
