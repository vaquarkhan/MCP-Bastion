import json

from mcp_bastion.doctor import scan_host_mcp_configs


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
