"""
Tests for the CRT HTTP read API (src/crt/server.py).

Run from project root:
    python -m pytest tests/test_crt_server.py -v
"""

from __future__ import annotations

import json

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from src.crt.server import CRTServer


@pytest.fixture()
def client() -> TestClient:
    server = CRTServer(seed_demo=True)
    app = Starlette(routes=server.routes())
    return TestClient(app, raise_server_exceptions=True)


# ── List campaigns ────────────────────────────────────────────────────────────

def test_list_campaigns_ok(client: TestClient) -> None:
    resp = client.get("/crt/campaigns")
    assert resp.status_code == 200
    data = resp.json()
    assert "campaigns" in data
    assert data["count"] >= 1


def test_list_campaigns_has_expected_fields(client: TestClient) -> None:
    c = client.get("/crt/campaigns").json()["campaigns"][0]
    for field in ("campaign_id", "target_id", "status", "participating_orgs_count", "coverage_fraction"):
        assert field in c, f"missing field: {field}"


def test_list_campaigns_no_org_id(client: TestClient) -> None:
    """Privacy: org_id must never appear in the campaigns list."""
    assert "org_id" not in client.get("/crt/campaigns").text


def test_demo_campaign_is_completed(client: TestClient) -> None:
    c = client.get("/crt/campaigns").json()["campaigns"][0]
    assert c["status"] == "completed"


# ── Campaign detail ───────────────────────────────────────────────────────────

def test_get_campaign_ok(client: TestClient) -> None:
    cid = client.get("/crt/campaigns").json()["campaigns"][0]["campaign_id"]
    resp = client.get(f"/crt/campaigns/{cid}")
    assert resp.status_code == 200
    data = resp.json()
    assert "campaign" in data
    assert "coverage_fraction" in data
    assert "diversity_score" in data
    assert "participating_orgs_count" in data


def test_get_campaign_no_enrolled_org_ids(client: TestClient) -> None:
    """Privacy: enrolled_org_ids directly exposes participant identities — must be excluded."""
    cid = client.get("/crt/campaigns").json()["campaigns"][0]["campaign_id"]
    text = client.get(f"/crt/campaigns/{cid}").text
    assert "enrolled_org_ids" not in text
    assert "org_id" not in text
    assert "org-alpha" not in text
    assert "org-beta" not in text
    assert "org-gamma" not in text


def test_get_campaign_not_found(client: TestClient) -> None:
    assert client.get("/crt/campaigns/nonexistent-id").status_code == 404


# ── Coverage ──────────────────────────────────────────────────────────────────

def test_get_coverage_ok(client: TestClient) -> None:
    cid = client.get("/crt/campaigns").json()["campaigns"][0]["campaign_id"]
    resp = client.get(f"/crt/campaigns/{cid}/coverage")
    assert resp.status_code == 200


def test_get_coverage_no_org_id(client: TestClient) -> None:
    """Privacy invariant: org_id must not appear anywhere in the coverage response."""
    cid = client.get("/crt/campaigns").json()["campaigns"][0]["campaign_id"]
    resp = client.get(f"/crt/campaigns/{cid}/coverage")
    data = resp.json()
    assert "org_id" not in data
    assert "org_id" not in json.dumps(data)


def test_get_coverage_all_six_leaves(client: TestClient) -> None:
    cid = client.get("/crt/campaigns").json()["campaigns"][0]["campaign_id"]
    data = client.get(f"/crt/campaigns/{cid}/coverage").json()
    assert data["total_leaves"] == 6
    assert len(data["leaf_coverage"]) == 6
    assert len(data["leaf_scores"]) == 6


def test_get_coverage_full_demo(client: TestClient) -> None:
    cid = client.get("/crt/campaigns").json()["campaigns"][0]["campaign_id"]
    data = client.get(f"/crt/campaigns/{cid}/coverage").json()
    assert data["covered_leaves"] == 6
    assert abs(data["coverage_fraction"] - 1.0) < 1e-4


def test_get_coverage_not_found(client: TestClient) -> None:
    assert client.get("/crt/campaigns/ghost/coverage").status_code == 404


# ── Report ────────────────────────────────────────────────────────────────────

def test_get_report_ok(client: TestClient) -> None:
    cid = client.get("/crt/campaigns").json()["campaigns"][0]["campaign_id"]
    resp = client.get(f"/crt/campaigns/{cid}/report")
    assert resp.status_code == 200


def test_get_report_has_hash(client: TestClient) -> None:
    cid = client.get("/crt/campaigns").json()["campaigns"][0]["campaign_id"]
    data = client.get(f"/crt/campaigns/{cid}/report").json()
    assert "report_hash" in data
    assert len(data["report_hash"]) == 64  # SHA3-256 hex


def test_get_report_no_org_id(client: TestClient) -> None:
    """Privacy invariant: org_id must not appear in the report."""
    cid = client.get("/crt/campaigns").json()["campaigns"][0]["campaign_id"]
    data = client.get(f"/crt/campaigns/{cid}/report").json()
    assert "org_id" not in json.dumps(data)


def test_get_report_threshold_met_on_full_demo(client: TestClient) -> None:
    cid = client.get("/crt/campaigns").json()["campaigns"][0]["campaign_id"]
    data = client.get(f"/crt/campaigns/{cid}/report").json()
    assert data["min_threshold_met"] is True


def test_get_report_not_found(client: TestClient) -> None:
    assert client.get("/crt/campaigns/ghost/report").status_code == 404


# ── Fixture route ─────────────────────────────────────────────────────────────

def test_fixture_route_returns_sample_data(client: TestClient) -> None:
    resp = client.get("/crt/fixture")
    assert resp.status_code == 200
    data = resp.json()
    assert "campaign_id" in data
    assert "report_hash" in data
    assert "leaf_coverage" in data


def test_fixture_report_hash_is_64_chars(client: TestClient) -> None:
    """Fixture hash must be a valid SHA3-256 hex digest (64 chars)."""
    data = client.get("/crt/fixture").json()
    h = data["report_hash"]
    assert len(h) == 64, f"report_hash is {len(h)} chars, expected 64"
    assert all(c in "0123456789abcdef" for c in h), "report_hash contains non-hex chars"
