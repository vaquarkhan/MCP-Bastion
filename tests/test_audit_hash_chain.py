"""Tests for tamper-evident audit hash chain."""

from mcp_bastion.pillars.audit_hash_chain import AuditHashChain, canonical_audit_payload, entry_digest


def test_chain_links_entries():
    AuditHashChain.configure(anchor_every=0)
    c = AuditHashChain.get()
    c.reset()
    a: dict = {"tool": "x", "action": "ALLOWED"}
    b: dict = {"tool": "y", "action": "BLOCKED", "reason": "nope"}
    c.append(a)
    c.append(b)
    assert a["audit_chain_index"] == 0
    assert b["audit_chain_index"] == 1
    assert b["audit_prev_hash"] == a["audit_entry_hash"]
    body_b = canonical_audit_payload(b)
    assert entry_digest(b["audit_prev_hash"], body_b) == b["audit_entry_hash"]


def test_verify_recent_detects_tamper():
    AuditHashChain.configure(anchor_every=0)
    c = AuditHashChain.get()
    c.reset()
    e1: dict = {"k": 1}
    e2: dict = {"k": 2}
    c.append(e1)
    c.append(e2)
    ok = [dict(e1), dict(e2)]
    assert AuditHashChain.get().verify_recent(ok)["valid"] is True
    bad = [dict(e1), dict(e2)]
    bad[1]["tool"] = "tampered"
    assert AuditHashChain.get().verify_recent(bad)["valid"] is False


def test_anchor_periodic():
    AuditHashChain.configure(anchor_every=1)
    c = AuditHashChain.get()
    c.reset()
    e1: dict = {"a": 1}
    e2: dict = {"a": 2}
    c.append(e1)
    c.append(e2)
    assert isinstance(e1.get("audit_anchor"), dict)
    assert e1["audit_anchor"]["head_hash"] == e1["audit_entry_hash"]
    assert isinstance(e2.get("audit_anchor"), dict)
    head = c.head()
    assert head["chain_length"] == 2
    AuditHashChain.configure(anchor_every=0)
