"""
UI integration tests — Prompt 5 panels

Tests all 5 new routes (monitor, sheila, zk-trail, dpo, redteam),
SSE stream, API endpoints, gate tests G6–G13, and CoT mismatch banner.

Run: pytest tests/test_ui_prompt5.py -v
"""

from __future__ import annotations

import os
import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from starlette.testclient import TestClient


# ── App fixture ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    os.environ["SARA_TEST_MODE"] = "true"

    from src.arena.store import ArenaStore
    from src.ui.portal import UIPortal

    store = MagicMock(spec=ArenaStore)
    store.list_active_bounties = AsyncMock(return_value=[])
    store.list_all_bounties = AsyncMock(return_value=[])
    store.list_payments = AsyncMock(return_value=[])
    store.get_bounty = AsyncMock(return_value=None)
    store.save_bounty = AsyncMock(return_value=None)
    store.get_attestation = AsyncMock(return_value=None)
    store.pause_bounty = AsyncMock(return_value=True)
    store.resume_bounty = AsyncMock(return_value=True)
    store.list_stalled_submissions = AsyncMock(return_value=[])

    portal = UIPortal(store=store)

    from starlette.applications import Starlette
    from starlette.routing import Route

    app = Starlette(routes=portal.routes())
    return TestClient(app, raise_server_exceptions=False)


# ── Panel routes — 200 ────────────────────────────────────────────────────────

def test_monitor_panel_returns_200(client):
    r = client.get("/monitor")
    assert r.status_code == 200
    assert "Safety Monitor" in r.text


def test_sheila_panel_returns_200(client):
    r = client.get("/sheila")
    assert r.status_code == 200
    assert "Sheila" in r.text


def test_zk_trail_panel_returns_200(client):
    r = client.get("/zk-trail")
    assert r.status_code == 200
    assert "ZK Audit Trail" in r.text


def test_dpo_panel_returns_200(client):
    r = client.get("/dpo")
    assert r.status_code == 200
    assert "DPO" in r.text


def test_redteam_panel_returns_200(client):
    r = client.get("/redteam")
    assert r.status_code == 200
    assert "Red Team" in r.text


# ── Nav links present ─────────────────────────────────────────────────────────

def test_monitor_page_has_nav_links(client):
    r = client.get("/monitor")
    for href in ["/sheila", "/zk-trail", "/dpo", "/redteam"]:
        assert href in r.text, f"Expected nav link {href} in /monitor"


def test_sheila_page_has_active_class(client):
    r = client.get("/sheila")
    assert 'class="active"' in r.text or "active" in r.text


# ── SSE stream endpoint ───────────────────────────────────────────────────────

def test_monitor_stream_endpoint_exists(client):
    r = client.get("/monitor/stream", headers={"Accept": "text/event-stream"}, timeout=2)
    assert r.status_code == 200


# ── API endpoints ─────────────────────────────────────────────────────────────

def test_verify_attestation_returns_json(client):
    r = client.get("/sheila/verify/att_test_abc123")
    assert r.status_code in (200, 404)
    d = r.json()
    assert "valid" in d
    assert "attestation_id" in d


def test_zk_verify_returns_json(client):
    r = client.get("/zk-trail/verify/att_test_xyz")
    assert r.status_code in (200, 404)
    d = r.json()
    assert "valid" in d


def test_build_dpo_dataset_endpoint_accepts_post(client):
    r = client.post("/dpo/build")
    assert r.status_code == 200
    d = r.json()
    assert d.get("status") == "building"


def test_dpo_status_returns_json(client):
    r = client.get("/dpo/status")
    assert r.status_code == 200
    d = r.json()
    assert "dataset_exists" in d


def test_dpo_add_evasion_requires_evasion_id(client):
    r = client.post("/dpo/add-evasion", json={})
    assert r.status_code == 400
    r2 = client.post("/dpo/add-evasion", json={"evasion_id": "ev_test_001"})
    assert r2.status_code == 200
    assert r2.json().get("status") == "queued"


def test_dpo_upload_labels_accepts_list(client):
    pairs = [{"chosen": "c1", "rejected": "r1"}, {"chosen": "c2", "rejected": "r2"}]
    r = client.post("/dpo/upload-labels", json=pairs)
    assert r.status_code == 200
    assert r.json().get("pairs_received") == 2


def test_run_redteam_accepts_post(client):
    r = client.post("/redteam/run", data={"n_probes": "10"})
    assert r.status_code == 200
    d = r.json()
    assert d.get("status") == "running"
    assert "session_id" in d


def test_redteam_report_returns_html(client):
    r = client.get("/redteam/report/sess_test123")
    assert r.status_code == 200
    assert "sess_test123" in r.text


# ── Gate tests G6–G13 ─────────────────────────────────────────────────────────

def test_gate_g6_commitment_roundtrip(client):
    r = client.post("/ui/test/gate6")
    assert r.status_code == 200
    d = r.json()
    assert d["pass"] is True, f"G6 failed: {d.get('detail')}"


def test_gate_g7_attestation_sign_verify(client):
    r = client.post("/ui/test/gate7")
    assert r.status_code == 200
    d = r.json()
    assert d["pass"] is True, f"G7 failed: {d.get('detail')}"


def test_gate_g8_chain_integrity(client):
    r = client.post("/ui/test/gate8")
    assert r.status_code == 200
    d = r.json()
    assert d["pass"] is True, f"G8 failed: {d.get('detail')}"
    assert d.get("chain_length") == 3


def test_gate_g9_gdpr_hash(client):
    r = client.post("/ui/test/gate9")
    assert r.status_code == 200
    d = r.json()
    assert d["pass"] is True, f"G9 failed: {d.get('detail')}"


def test_gate_g10_sheila_boundary_no_internal_imports(client):
    r = client.post("/ui/test/gate10")
    assert r.status_code == 200
    d = r.json()
    assert d["pass"] is True, f"G10 failed — violations: {d.get('violations')}"


def test_gate_g11_monitor_rules(client):
    r = client.post("/ui/test/gate11")
    assert r.status_code == 200
    d = r.json()
    assert d["pass"] is True, f"G11 failed: {d.get('detail')}"
    assert d.get("action") in ("block", "flag", "escalate", "forward_to_sheila")


def test_gate_g12_cot_capture(client):
    r = client.post("/ui/test/gate12")
    assert r.status_code == 200
    d = r.json()
    assert d["pass"] is True, f"G12 failed: {d.get('detail')}"
    assert d.get("thinking_chars", 0) > 0


def test_gate_g13_all_dpo_pairs_have_cot(client):
    r = client.post("/ui/test/gate13")
    assert r.status_code == 200
    d = r.json()
    assert d["pass"] is True, f"G13 failed: {d.get('detail')}"
    assert d.get("missing_cot", 1) == 0


# ── CoT mismatch banner ───────────────────────────────────────────────────────

def test_sheila_panel_shows_cot_mismatch_banner_element(client):
    r = client.get("/sheila")
    assert "cot-mismatch-banner" in r.text
    assert "CoT mismatch" in r.text or "cot_mismatch" in r.text.lower() or "CoT mismatches" in r.text


# ── Tan theme applied ─────────────────────────────────────────────────────────

def test_tan_background_in_monitor(client):
    r = client.get("/monitor")
    assert "#d2b48c" in r.text, "Tan background not applied to monitor page"


def test_tan_background_in_sheila(client):
    r = client.get("/sheila")
    assert "#d2b48c" in r.text


def test_black_font_in_zk_trail(client):
    r = client.get("/zk-trail")
    assert "#111111" in r.text, "Black font not applied to zk-trail page"
