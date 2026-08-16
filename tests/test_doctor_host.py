import json

from mcp_bastion.doctor import run_doctor, scan_host_mcp_configs


def test_host_scan_is_advisory_and_flags_cleartext_and_unapproved_writes(tmp_path, monkeypatch):
    appdata = tmp_path / "AppData" / "Roaming"
    config = appdata / "Cursor" / "User" / "mcp.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem-write": {"url": "http://remote.example:8080/mcp"}
                },
                "egress_allowlist": {"enabled": True, "hosts": []},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("APPDATA", str(appdata))
    reports = scan_host_mcp_configs(tmp_path)
    report = next(item for item in reports if item["path"] == str(config))
    assert report["advisory"] is True
    ids = {finding["id"] for finding in report["findings"]}
    assert {"writes_without_approval", "empty_egress_allowlist", "http_without_tls"} <= ids


def test_host_scan_missing_files_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path / "missing"))
    assert scan_host_mcp_configs(tmp_path) == []


def test_host_scan_unreadable_and_loopback_ok(tmp_path, monkeypatch):
    appdata = tmp_path / "AppData" / "Roaming"
    bad = appdata / "Cursor" / "User" / "mcp.json"
    bad.parent.mkdir(parents=True)
    bad.write_text("{not-json", encoding="utf-8")
    good = tmp_path / ".cursor" / "mcp.json"
    good.parent.mkdir(parents=True)
    good.write_text(
        json.dumps({"mcpServers": {"local": {"url": "http://127.0.0.1:3000/mcp"}}}),
        encoding="utf-8",
    )
    gs = appdata / "Cursor" / "User" / "globalStorage" / "ext"
    gs.mkdir(parents=True)
    (gs / "mcp-settings.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("APPDATA", str(appdata))
    reports = scan_host_mcp_configs(tmp_path)
    by_path = {r["path"]: r for r in reports}
    assert any(f["id"] == "config_unreadable" for f in by_path[str(bad)]["findings"])
    assert by_path[str(good)]["findings"] == []


def test_run_doctor_host_section(tmp_path, monkeypatch):
    import builtins

    monkeypatch.setenv("APPDATA", str(tmp_path / "missing"))
    monkeypatch.setattr("mcp_bastion.doctor.shutil.which", lambda _name: None)
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "pip_audit" or str(name).startswith("pip_audit."):
            raise ImportError("skip")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    report = run_doctor(config_path=None, repo_root=tmp_path, host=True)
    assert "host_scan" in report
    assert report["host_scan"]["advisory"] is True
    assert isinstance(report["host_scan"]["configs"], list)
