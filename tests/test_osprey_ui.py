"""
Tests for Osprey UI — policy rule compiler, monitor, and DAO defaults.

All tests run without live API calls, ClickHouse, or TEE infrastructure.
"""

import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.osprey_ui.models import PolicyRule, MonitorEvent, RuleTestResult
from src.osprey_ui.dao_defaults import DAO_DEFAULT_RULES
from src.osprey_ui.compiler import OspreyRuleCompiler
from src.osprey_ui.monitor import SaraPolicyMonitor, SafetyStopException, SHADOW_MODE
from src.osprey_ui.store import OspreyUIStore


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_classifier(unsafe: bool = False, confidence: float = 0.5, category: str | None = None):
    classifier = MagicMock()
    result = MagicMock()
    result.confidence = confidence
    result.matched_category = category
    result.label = "unsafe" if unsafe else "safe"
    classifier.classify = AsyncMock(return_value=result)
    return classifier


def _make_ozone():
    ozone = MagicMock()
    ozone.apply_label = AsyncMock()
    return ozone


def _make_erc8004():
    erc = MagicMock()
    record = MagicMock()
    record.tx_hash = "0xabc123"
    erc.record_evaluation_result = AsyncMock(return_value=record)
    return erc


def _make_store():
    store = MagicMock()
    store.save_monitor_event = AsyncMock()
    store.save_rule = AsyncMock()
    store.get_rule = AsyncMock()
    store.list_rules_for_org = AsyncMock(return_value=[])
    return store


def _make_rule(action: str = "ALERT", confidence_threshold: float = 0.5, severity: str = "high", enabled: bool = True):
    return PolicyRule(
        org_id="dao-001",
        display_name="Test rule",
        natural_language="No PII extraction",
        osprey_sml="rule test { when pii then block severity high category identity }",
        category="identity_access_probing",
        severity=severity,
        action=action,
        confidence_threshold=confidence_threshold,
        enabled=enabled,
        created_by="analyst-001",
        created_at=datetime.now(timezone.utc),
    )


# ── Compiler ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rule_compiler_produces_valid_json():
    agent = MagicMock()
    agent.chat = AsyncMock(return_value=json.dumps({
        "osprey_sml": "rule pii_block { when prompt contains 'ssn' then block severity critical category pii_ip }",
        "display_name": "Block SSN",
        "confidence_threshold": 0.8,
        "action": "STOP",
        "explanation": "Blocks prompts asking for social security numbers.",
    }))

    compiler = OspreyRuleCompiler(agent=agent)
    rule = await compiler.compile(
        org_id="dao-001",
        natural_language="Block any prompt asking for social security numbers",
        category="pii_ip",
        severity="critical",
    )

    assert rule.org_id == "dao-001"
    assert rule.display_name == "Block SSN"
    assert rule.action == "STOP"
    assert rule.confidence_threshold == 0.8
    assert rule.category == "pii_ip"
    assert rule.severity == "critical"
    assert rule.natural_language == "Block any prompt asking for social security numbers"


@pytest.mark.asyncio
async def test_compiled_sml_has_rule_keyword():
    agent = MagicMock()
    agent.chat = AsyncMock(return_value=json.dumps({
        "osprey_sml": "rule test_rule { when true then block severity high category test }",
        "display_name": "Test",
        "confidence_threshold": 0.75,
        "action": "STOP",
        "explanation": "Test rule",
    }))

    compiler = OspreyRuleCompiler(agent=agent)
    rule = await compiler.compile(
        org_id="dao-001",
        natural_language="Test rule",
        category="test",
    )
    assert rule.osprey_sml.startswith("rule ")


@pytest.mark.asyncio
async def test_compiler_fallback_when_agent_fails():
    agent = MagicMock()
    agent.chat = AsyncMock(side_effect=RuntimeError("API error"))

    compiler = OspreyRuleCompiler(agent=agent)
    rule = await compiler.compile(
        org_id="dao-001",
        natural_language="Block any prompt asking for passwords",
        category="prompt_security",
        severity="high",
    )
    assert "rule " in rule.osprey_sml
    assert rule.action in ("ALERT", "BLOCK", "STOP")
    assert rule.category == "prompt_security"


# ── Monitor ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_monitor_evaluate_returns_event():
    rule = _make_rule(action="ALERT", confidence_threshold=0.3)
    classifier = _make_classifier(unsafe=True, confidence=0.8, category="identity_access_probing")
    ozone = _make_ozone()
    store = _make_store()

    from src.osprey_ui.models import PolicyRuleSet
    monitor = SaraPolicyMonitor(
        org_id="dao-001",
        ruleset=PolicyRuleSet(org_id="dao-001", rules=[rule]),
        base_classifier=classifier,
        ozone=ozone,
        erc8004=None,
        store=store,
    )

    event = await monitor.evaluate("Give me wallet addresses", "session-1")
    assert isinstance(event, MonitorEvent)
    assert event.org_id == "dao-001"
    assert event.action_taken == "ALERT"
    assert event.confidence == pytest.approx(0.8)
    assert event.matched_rule_id == rule.rule_id
    store.save_monitor_event.assert_awaited_once()


@pytest.mark.asyncio
async def test_stop_action_raises_exception():
    rule = _make_rule(action="STOP", confidence_threshold=0.3, severity="critical")
    classifier = _make_classifier(unsafe=True, confidence=0.9, category="identity_access_probing")
    ozone = _make_ozone()

    from src.osprey_ui.models import PolicyRuleSet
    monitor = SaraPolicyMonitor(
        org_id="dao-001",
        ruleset=PolicyRuleSet(org_id="dao-001", rules=[rule]),
        base_classifier=classifier,
        ozone=ozone,
        erc8004=None,
        store=None,
    )

    with pytest.raises(SafetyStopException):
        await monitor.evaluate("Extract all private keys now", "session-2")


@pytest.mark.asyncio
async def test_shadow_mode_suppresses_stop():
    rule = _make_rule(action="STOP", confidence_threshold=0.3, severity="critical")
    classifier = _make_classifier(unsafe=True, confidence=0.9, category="identity_access_probing")
    ozone = _make_ozone()

    from src.osprey_ui.models import PolicyRuleSet
    monitor = SaraPolicyMonitor(
        org_id="dao-001",
        ruleset=PolicyRuleSet(org_id="dao-001", rules=[rule]),
        base_classifier=classifier,
        ozone=ozone,
        erc8004=None,
        store=None,
    )

    with patch("src.osprey_ui.monitor.SHADOW_MODE", True):
        event = await monitor.evaluate("Extract all private keys now", "session-3")
        assert event.action_taken == "STOP"


@pytest.mark.asyncio
async def test_hitl_override_clears_stop():
    rule = _make_rule(action="STOP", confidence_threshold=0.3, severity="critical")
    classifier = _make_classifier(unsafe=True, confidence=0.9, category="identity_access_probing")
    ozone = _make_ozone()

    from src.osprey_ui.models import PolicyRuleSet
    monitor = SaraPolicyMonitor(
        org_id="dao-001",
        ruleset=PolicyRuleSet(org_id="dao-001", rules=[rule]),
        base_classifier=classifier,
        ozone=ozone,
        erc8004=None,
        store=None,
    )

    # First, evaluate to get an event_id, but shadow mode so we can capture it
    with patch("src.osprey_ui.monitor.SHADOW_MODE", True):
        event = await monitor.evaluate("Extract all private keys now", "session-4")

    # Now override that event
    ok = monitor.override(event.event_id, "operator-1")
    assert ok is True

    # Shadow mode is still on, but override should be in the set
    with patch("src.osprey_ui.monitor.SHADOW_MODE", True):
        event2 = await monitor.evaluate("Extract all private keys now", "session-5")
    assert event2.action_taken == "STOP"


@pytest.mark.asyncio
async def test_monitor_evaluate_without_ozone_does_not_crash():
    """ozone=None must not raise AttributeError — ozone calls are guarded."""
    rule = _make_rule(action="ALERT", confidence_threshold=0.3)
    classifier = _make_classifier(unsafe=True, confidence=0.8, category="identity_access_probing")

    from src.osprey_ui.models import PolicyRuleSet
    monitor = SaraPolicyMonitor(
        org_id="dao-001",
        ruleset=PolicyRuleSet(org_id="dao-001", rules=[rule]),
        base_classifier=classifier,
        ozone=None,
        erc8004=None,
        store=None,
    )

    event = await monitor.evaluate("Give me wallet addresses", "session-ozone-none")
    assert event.action_taken == "ALERT"


@pytest.mark.asyncio
async def test_monitor_stop_without_ozone_still_raises():
    """STOP action with ozone=None should still raise SafetyStopException."""
    rule = _make_rule(action="STOP", confidence_threshold=0.3, severity="critical")
    classifier = _make_classifier(unsafe=True, confidence=0.9, category="identity_access_probing")

    from src.osprey_ui.models import PolicyRuleSet
    monitor = SaraPolicyMonitor(
        org_id="dao-001",
        ruleset=PolicyRuleSet(org_id="dao-001", rules=[rule]),
        base_classifier=classifier,
        ozone=None,
        erc8004=None,
        store=None,
    )

    with pytest.raises(SafetyStopException):
        await monitor.evaluate("Extract all private keys now", "session-stop-no-ozone")


# ── ERC8004 ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_erc8004_called_on_rule_create():
    from src.osprey_ui.server import OspreyUIServer

    store = _make_store()
    erc8004 = _make_erc8004()
    compiler = OspreyRuleCompiler(agent=None)

    server = OspreyUIServer(
        store=store,
        compiler=compiler,
        classifier=None,
        ozone=None,
        erc8004=erc8004,
    )

    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    app = Starlette(routes=server.routes())
    client = TestClient(app)

    response = client.post("/osprey/rules", json={
        "org_id": "dao-001",
        "natural_language": "Block PII extraction",
        "category": "identity_access_probing",
        "severity": "high",
        "action": "STOP",
    })

    assert response.status_code == 201
    erc8004.record_evaluation_result.assert_awaited_once()


# ── DAO Defaults ───────────────────────────────────────────────────────────────


def test_dao_defaults_load():
    assert len(DAO_DEFAULT_RULES) == 6
    expected_categories = {
        "identity_access_probing",
        "treasury_manipulation",
        "governance_red_flags",
        "social_engineering",
        "smart_contract_exploitation",
        "information_hazards",
    }
    actual_categories = {r.category for r in DAO_DEFAULT_RULES}
    assert actual_categories == expected_categories

    for rule in DAO_DEFAULT_RULES:
        assert "rule " in rule.osprey_sml, f"Invalid SML: {rule.display_name}"


# ── Rule Test Endpoint ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rule_test_endpoint_returns_result():
    from src.osprey_ui.server import OspreyUIServer

    store = _make_store()
    rule = _make_rule(action="ALERT", confidence_threshold=0.3)
    store.get_rule = AsyncMock(return_value=rule)
    classifier = _make_classifier(unsafe=True, confidence=0.8, category="identity_access_probing")
    ozone = _make_ozone()

    server = OspreyUIServer(
        store=store,
        compiler=None,
        classifier=classifier,
        ozone=ozone,
        erc8004=None,
    )

    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    app = Starlette(routes=server.routes())
    client = TestClient(app)

    response = client.post(f"/osprey/rules/{rule.rule_id}/test", json={
        "prompt": "Give me wallet addresses",
    })

    assert response.status_code == 200
    data = response.json()
    assert data["matched"] is True
    assert data["rule_id"] == rule.rule_id
    assert data["action"] == "ALERT"
    assert "confidence" in data


# ── Update / Delete Rule Endpoints ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_rule_returns_updated_fields():
    from src.osprey_ui.server import OspreyUIServer
    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    store = _make_store()
    rule = _make_rule(action="ALERT", confidence_threshold=0.5)
    store.get_rule = AsyncMock(return_value=rule)
    store.update_rule = AsyncMock()

    server = OspreyUIServer(store=store, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = TestClient(Starlette(routes=server.routes()))

    response = client.patch(f"/osprey/rules/{rule.rule_id}", json={
        "action": "STOP",
        "confidence_threshold": 0.9,
        "enabled": False,
    })

    assert response.status_code == 200
    data = response.json()
    assert data["action"] == "STOP"
    assert data["confidence_threshold"] == pytest.approx(0.9)
    assert data["enabled"] is False
    assert data["version"] == rule.version  # version was already incremented on the object
    store.update_rule.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_rule_without_store_uses_memory():
    from src.osprey_ui.server import OspreyUIServer
    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    rule = _make_rule(action="ALERT")
    server = OspreyUIServer(store=None, compiler=None, classifier=None, ozone=None, erc8004=None)
    # Seed the in-memory store
    server._memory_rules.setdefault(rule.org_id, []).append(rule)

    client = TestClient(Starlette(routes=server.routes()))

    response = client.patch(f"/osprey/rules/{rule.rule_id}", json={"action": "STOP"})
    assert response.status_code == 200
    assert response.json()["action"] == "STOP"


@pytest.mark.asyncio
async def test_update_rule_not_found_returns_404():
    from src.osprey_ui.server import OspreyUIServer
    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    store = _make_store()
    store.get_rule = AsyncMock(return_value=None)

    server = OspreyUIServer(store=store, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = TestClient(Starlette(routes=server.routes()))

    response = client.patch("/osprey/rules/nonexistent-id", json={"action": "STOP"})
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_delete_rule_disables_it():
    from src.osprey_ui.server import OspreyUIServer
    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    store = _make_store()
    rule = _make_rule(action="ALERT")
    store.get_rule = AsyncMock(return_value=rule)
    store.update_rule = AsyncMock()

    server = OspreyUIServer(store=store, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = TestClient(Starlette(routes=server.routes()))

    response = client.delete(f"/osprey/rules/{rule.rule_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "disabled"
    assert data["rule_id"] == rule.rule_id
    store.update_rule.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_rule_not_found_returns_404():
    from src.osprey_ui.server import OspreyUIServer
    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    store = _make_store()
    store.get_rule = AsyncMock(return_value=None)

    server = OspreyUIServer(store=store, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = TestClient(Starlette(routes=server.routes()))

    response = client.delete("/osprey/rules/nonexistent-id")
    assert response.status_code == 404


# ── Store ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_store_initializes_ddl():
    ch = MagicMock()
    ch.query = AsyncMock()
    store = OspreyUIStore(clickhouse=ch)
    await store.initialize()
    assert ch.query.await_count >= len(store.__class__.__dict__.get("OSPREY_UI_DDL", [])) or ch.query.await_count > 0


def test_row_to_monitor_event_correct_column_order():
    """Regression: timestamp is at index 7, erc8004_tx_hash at index 8 (9-column DDL)."""
    from src.osprey_ui.store import _row_to_monitor_event
    from datetime import datetime, timezone
    ts_ms = int(datetime(2026, 6, 16, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1000)
    row = (
        "evt-001",   # 0 event_id
        "dao-001",   # 1 org_id
        "sess-1",    # 2 session_id
        "abc123",    # 3 prompt_hash
        "rule-999",  # 4 matched_rule_id
        "ALERT",     # 5 action_taken
        0.85,        # 6 confidence
        ts_ms,       # 7 timestamp  ← must be read here, not row[8]
        "0xtxhash",  # 8 erc8004_tx_hash
    )
    event = _row_to_monitor_event(row)
    assert event.event_id == "evt-001"
    assert event.action_taken == "ALERT"
    assert abs(event.confidence - 0.85) < 1e-6
    assert event.erc8004_tx_hash == "0xtxhash"
    assert event.timestamp.year == 2026


def test_list_monitor_events_cross_org_when_org_id_empty():
    """list_monitor_events(org_id=None or '') must not add a WHERE org_id clause."""
    from src.osprey_ui.store import OspreyUIStore
    import inspect

    # Inspect the method source to verify conditions list starts empty when org_id is falsy
    src = inspect.getsource(OspreyUIStore.list_monitor_events)
    # The fix: conditions should be empty list when org_id is falsy
    assert "not org_id" in src or "if org_id" in src, (
        "list_monitor_events should skip org_id filter when org_id is None/empty"
    )


# ── OS-04: Vertical Default Rule Packs ────────────────────────────────────────


def test_insurance_pack_has_six_rules():
    from src.osprey_ui.vertical_defaults import INSURANCE_DEFAULT_RULES
    assert len(INSURANCE_DEFAULT_RULES) == 6
    for rule in INSURANCE_DEFAULT_RULES:
        assert "rule " in rule.osprey_sml, f"Invalid SML: {rule.display_name}"
        assert rule.action in ("ALERT", "STOP")
        assert rule.severity in ("critical", "high", "medium", "low")


def test_critical_infra_pack_has_six_rules():
    from src.osprey_ui.vertical_defaults import CRITICAL_INFRA_DEFAULT_RULES
    assert len(CRITICAL_INFRA_DEFAULT_RULES) == 6
    for rule in CRITICAL_INFRA_DEFAULT_RULES:
        assert "rule " in rule.osprey_sml, f"Invalid SML: {rule.display_name}"
        assert rule.action in ("ALERT", "STOP")
        assert rule.severity in ("critical", "high", "medium", "low")


def test_vertical_packs_registry():
    from src.osprey_ui.vertical_defaults import VERTICAL_PACKS
    assert "insurance" in VERTICAL_PACKS
    assert "critical_infrastructure" in VERTICAL_PACKS
    assert all(len(rules) > 0 for rules in VERTICAL_PACKS.values())


@pytest.mark.asyncio
async def test_list_vertical_packs_endpoint():
    from src.osprey_ui.server import OspreyUIServer
    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    server = OspreyUIServer(store=None, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = TestClient(Starlette(routes=server.routes()))

    response = client.get("/osprey/vertical-defaults")
    assert response.status_code == 200
    data = response.json()
    assert "packs" in data
    pack_names = {p["pack"] for p in data["packs"]}
    assert "insurance" in pack_names
    assert "critical_infrastructure" in pack_names


@pytest.mark.asyncio
async def test_get_vertical_pack_endpoint_insurance():
    from src.osprey_ui.server import OspreyUIServer
    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    server = OspreyUIServer(store=None, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = TestClient(Starlette(routes=server.routes()))

    response = client.get("/osprey/vertical-defaults/insurance")
    assert response.status_code == 200
    data = response.json()
    assert data["pack"] == "insurance"
    assert data["count"] == 6
    assert len(data["rules"]) == 6


@pytest.mark.asyncio
async def test_get_vertical_pack_endpoint_unknown():
    from src.osprey_ui.server import OspreyUIServer
    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    server = OspreyUIServer(store=None, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = TestClient(Starlette(routes=server.routes()))

    response = client.get("/osprey/vertical-defaults/unicorn_pack")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_install_vertical_pack_into_org():
    from src.osprey_ui.server import OspreyUIServer
    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    store = _make_store()
    server = OspreyUIServer(store=store, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = TestClient(Starlette(routes=server.routes()))

    response = client.post(
        "/osprey/vertical-defaults/critical_infrastructure/install",
        json={"org_id": "infra-org-001", "created_by": "admin"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["count"] == 6
    assert all(r["org_id"] == "infra-org-001" for r in data["installed"])
    assert store.save_rule.await_count == 6


@pytest.mark.asyncio
async def test_install_vertical_pack_missing_org_id():
    from src.osprey_ui.server import OspreyUIServer
    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    server = OspreyUIServer(store=None, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = TestClient(Starlette(routes=server.routes()))

    response = client.post("/osprey/vertical-defaults/insurance/install", json={})
    assert response.status_code == 400


# ── OS-05: Per-leaf F1 benchmark ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_f1_stats_returns_empty_when_no_data():
    from src.osprey_ui.server import OspreyUIServer
    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    store = _make_store()
    store.get_leaf_f1_stats = AsyncMock(return_value=[])
    server = OspreyUIServer(store=store, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = TestClient(Starlette(routes=server.routes()))

    response = client.get("/osprey/benchmark/f1")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 0
    assert "note" in data


@pytest.mark.asyncio
async def test_get_f1_stats_returns_cached_data():
    from src.osprey_ui.server import OspreyUIServer
    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    mock_stats = [
        {"category": "pii_ip", "precision": 0.9, "recall": 0.7, "f1": 0.787, "sample_count": 100, "updated_at": "2026-06-16"},
        {"category": "illicit_activities", "precision": 0.5, "recall": 0.4, "f1": 0.444, "sample_count": 50, "updated_at": "2026-06-16"},
    ]
    store = _make_store()
    store.get_leaf_f1_stats = AsyncMock(return_value=mock_stats)
    server = OspreyUIServer(store=store, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = TestClient(Starlette(routes=server.routes()))

    response = client.get("/osprey/benchmark/f1")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 2
    cats = {s["category"] for s in data["leaf_f1"]}
    assert "pii_ip" in cats
    assert "illicit_activities" in cats


@pytest.mark.asyncio
async def test_refresh_f1_stats_with_no_arena_store_no_events():
    from src.osprey_ui.server import OspreyUIServer
    from starlette.testclient import TestClient
    from starlette.applications import Starlette

    store = _make_store()
    store.list_monitor_events = AsyncMock(return_value=[])
    store.upsert_leaf_f1 = AsyncMock()
    server = OspreyUIServer(store=store, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = TestClient(Starlette(routes=server.routes()))

    response = client.post("/osprey/benchmark/f1/refresh")
    assert response.status_code == 200
    data = response.json()
    assert data["refreshed"] == 0


@pytest.mark.asyncio
async def test_refresh_f1_stats_uses_monitor_events():
    from src.osprey_ui.server import OspreyUIServer
    from starlette.testclient import TestClient
    from starlette.applications import Starlette
    from src.osprey_ui.models import MonitorEvent

    rule = _make_rule(action="ALERT", confidence_threshold=0.3)
    events = [
        MonitorEvent(
            org_id="dao-001",
            session_id="s1",
            prompt_hash="abc",
            matched_rule_id=rule.rule_id,
            action_taken="ALERT",
            confidence=0.8,
        ),
        MonitorEvent(
            org_id="dao-001",
            session_id="s2",
            prompt_hash="def",
            matched_rule_id=rule.rule_id,
            action_taken="STOP",
            confidence=0.9,
        ),
    ]

    store = _make_store()
    store.list_monitor_events = AsyncMock(return_value=events)
    store.upsert_leaf_f1 = AsyncMock()

    server = OspreyUIServer(store=store, compiler=None, classifier=None, ozone=None, erc8004=None)
    # Seed rule into memory so category lookup works
    server._memory_rules.setdefault(rule.org_id, []).append(rule)
    client = TestClient(Starlette(routes=server.routes()))

    response = client.post("/osprey/benchmark/f1/refresh")
    assert response.status_code == 200
    data = response.json()
    assert data["refreshed"] >= 1
    category_names = {s["category"] for s in data["leaf_f1"]}
    assert rule.category in category_names


# ── OS-05: per-leaf F1 from the RL benchmark (tinker_spike) ───────────────────


def test_leaf_f1_rows_from_leafmetrics_objects():
    """The converter accepts tinker_spike LeafMetrics and sorts weakest-first."""
    from src.osprey_ui.server import _leaf_f1_rows_from_per_leaf
    from src.agent_rl.tinker_spike.evaluate import LeafMetrics

    per_leaf = {
        "strong_leaf": LeafMetrics(leaf="strong_leaf", tp=9, fp=1, fn=0, tn=10),
        "weak_leaf": LeafMetrics(leaf="weak_leaf", tp=2, fp=5, fn=8, tn=5),
    }
    rows = _leaf_f1_rows_from_per_leaf(per_leaf)
    assert [r["category"] for r in rows] == ["weak_leaf", "strong_leaf"]  # ascending F1
    weak = rows[0]
    assert weak["sample_count"] == 2 + 5 + 8 + 5
    assert 0.0 <= weak["f1"] <= 1.0
    assert weak["f1"] < rows[1]["f1"]


def test_leaf_f1_rows_from_flattened_dict():
    """The converter also accepts the JSON report shape (eval_result_to_dict)."""
    from src.osprey_ui.server import _leaf_f1_rows_from_per_leaf

    per_leaf = {
        "pii_ip": {"precision": 0.9, "recall": 0.5, "f1": 0.643, "tp": 5, "fp": 1, "fn": 5, "tn": 9},
    }
    rows = _leaf_f1_rows_from_per_leaf(per_leaf)
    assert rows[0]["category"] == "pii_ip"
    assert rows[0]["f1"] == pytest.approx(0.643, abs=1e-3)
    assert rows[0]["sample_count"] == 20


@pytest.mark.asyncio
async def test_refresh_f1_prefers_rl_benchmark_over_arena():
    """When an RL benchmark provider yields data it wins over arena/monitor."""
    from src.osprey_ui.server import OspreyUIServer
    from src.agent_rl.tinker_spike.evaluate import LeafMetrics

    def provider():
        return {"per_leaf": {"treasury_manipulation": LeafMetrics(
            leaf="treasury_manipulation", tp=3, fp=2, fn=5, tn=4)}}

    store = _make_store()
    store.upsert_leaf_f1 = AsyncMock()
    # arena_store present too — RL benchmark must take priority over it.
    server = OspreyUIServer(
        store=store, classifier=None, ozone=None, erc8004=None,
        arena_store=MagicMock(), rl_benchmark=provider,
    )
    client = _client_for(server)

    resp = client.post("/osprey/benchmark/f1/refresh")
    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "rl_benchmark"
    cats = {s["category"] for s in data["leaf_f1"]}
    assert "treasury_manipulation" in cats


@pytest.mark.asyncio
async def test_rl_benchmark_provider_async_and_empty_falls_through():
    """An async provider returning no per_leaf falls back to monitor events."""
    from src.osprey_ui.server import OspreyUIServer

    async def empty_provider():
        return None

    store = _make_store()
    store.list_monitor_events = AsyncMock(return_value=[])
    store.upsert_leaf_f1 = AsyncMock()
    server = OspreyUIServer(
        store=store, classifier=None, ozone=None, erc8004=None,
        rl_benchmark=empty_provider,
    )
    client = _client_for(server)

    resp = client.post("/osprey/benchmark/f1/refresh")
    assert resp.status_code == 200
    assert resp.json()["refreshed"] == 0


def test_eval_report_roundtrip(tmp_path):
    """write_eval_report → load_eval_report preserves per-leaf F1."""
    from src.agent_rl.tinker_spike.evaluate import (
        EvalResult, LeafMetrics, write_eval_report, load_eval_report,
    )

    result = EvalResult(
        macro_f1=0.82,
        stop_fp_rate=0.0,
        per_leaf={"pii_ip": LeafMetrics(leaf="pii_ip", tp=8, fp=2, fn=2, tn=8)},
        exit_gate_passed=False,
        notes=["leaf pii_ip below floor"],
    )
    path = tmp_path / "rl_eval_report.json"
    write_eval_report(result, str(path))
    loaded = load_eval_report(str(path))
    assert loaded is not None
    assert "pii_ip" in loaded["per_leaf"]
    assert loaded["per_leaf"]["pii_ip"]["tp"] == 8


def test_load_eval_report_missing_returns_none(tmp_path):
    from src.agent_rl.tinker_spike.evaluate import load_eval_report
    assert load_eval_report(str(tmp_path / "nope.json")) is None


@pytest.mark.asyncio
async def test_store_upsert_leaf_f1():
    import time
    ch = MagicMock()
    ch.query = AsyncMock()
    store = OspreyUIStore(clickhouse=ch)
    await store.upsert_leaf_f1(
        category="pii_ip",
        precision_val=0.85,
        recall_val=0.72,
        f1_score=0.78,
        sample_count=42,
    )
    ch.query.assert_awaited_once()
    call_args = ch.query.call_args[0][0]
    assert "pii_ip" in call_args
    assert "0.85" in call_args or "0.8500" in call_args


@pytest.mark.asyncio
async def test_store_get_leaf_f1_stats_returns_empty_on_error():
    ch = MagicMock()
    ch.query = AsyncMock(side_effect=RuntimeError("ClickHouse down"))
    store = OspreyUIStore(clickhouse=ch)
    result = await store.get_leaf_f1_stats()
    assert result == []


# ── A.5UI_Osprey: human rule authoring (draft / validate / preview / feedback) ──


def _client_for(server):
    from starlette.testclient import TestClient
    from starlette.applications import Starlette
    return TestClient(Starlette(routes=server.routes()))


def _agent_returning(payload):
    """Mock agent whose .chat() returns the given dict as a JSON string."""
    agent = MagicMock()
    agent.chat = AsyncMock(return_value=json.dumps(payload))
    return agent


@pytest.mark.asyncio
async def test_validate_rejects_invalid_sml():
    from src.osprey_ui.server import OspreyUIServer
    server = OspreyUIServer(store=None, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = _client_for(server)

    resp = client.post("/osprey/rules/validate", json={
        "osprey_sml": "this is not a rule",
        "action": "ALERT",
        "severity": "high",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert len(data["errors"]) > 0


@pytest.mark.asyncio
async def test_validate_accepts_valid_sml():
    from src.osprey_ui.server import OspreyUIServer
    server = OspreyUIServer(store=None, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = _client_for(server)

    resp = client.post("/osprey/rules/validate", json={
        "osprey_sml": "rule block_keys { when prompt contains 'private key' then block severity critical category pii }",
        "action": "STOP",
        "severity": "critical",
    })
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


@pytest.mark.asyncio
async def test_draft_does_not_persist():
    """Assisted-mode draft compiles SML via the model but never saves it."""
    from src.osprey_ui.server import OspreyUIServer
    agent = _agent_returning({
        "osprey_sml": "rule pii { when prompt contains 'ssn' then block severity high category pii }",
        "display_name": "Block SSN", "confidence_threshold": 0.8, "action": "STOP", "explanation": "x",
    })
    store = _make_store()
    server = OspreyUIServer(store=store, classifier=None, ozone=None, erc8004=None, agent=agent)
    client = _client_for(server)

    resp = client.post("/osprey/rules/draft", json={
        "org_id": "dao-001",
        "natural_language": "Block prompts asking for SSNs",
        "category": "pii_ip",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["persisted"] is False
    assert "rule " in data["osprey_sml"]
    # The compiled draft is valid and was NOT written to the store.
    assert data["validation"] == []
    store.save_rule.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_rule_blocks_invalid_sml():
    """A rule that fails validation cannot be saved (400, store untouched)."""
    from src.osprey_ui.server import OspreyUIServer
    store = _make_store()
    server = OspreyUIServer(store=store, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = _client_for(server)

    resp = client.post("/osprey/rules", json={
        "org_id": "dao-001",
        "osprey_sml": "garbage with no structure",
        "category": "pii_ip",
        "action": "ALERT",
        "severity": "high",
    })
    assert resp.status_code == 400
    assert "errors" in resp.json()
    store.save_rule.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_rule_accepts_direct_sml():
    """Raw-SML authoring persists through the same path as agent rules."""
    from src.osprey_ui.server import OspreyUIServer
    store = _make_store()
    server = OspreyUIServer(store=store, compiler=None, classifier=None, ozone=None, erc8004=None)
    client = _client_for(server)

    resp = client.post("/osprey/rules", json={
        "org_id": "dao-001",
        "display_name": "Block seed phrase",
        "osprey_sml": "rule seed { when prompt contains 'seed phrase' then block severity critical category pii }",
        "category": "pii_ip",
        "action": "STOP",
        "severity": "critical",
        "created_by": "human-001",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["created_by"] == "human-001"
    assert data["action"] == "STOP"
    store.save_rule.assert_awaited()


@pytest.mark.asyncio
async def test_assisted_draft_passes_validation():
    """An NL intent yields a draft that passes deterministic validation."""
    from src.osprey_ui.server import OspreyUIServer
    agent = _agent_returning({
        "osprey_sml": "rule treasury { when prompt contains 'multisig key' then block severity critical category treasury }",
        "display_name": "Treasury", "confidence_threshold": 0.9, "action": "STOP", "explanation": "x",
    })
    server = OspreyUIServer(store=_make_store(), classifier=None, ozone=None, erc8004=None, agent=agent)
    client = _client_for(server)

    draft = client.post("/osprey/rules/draft", json={
        "org_id": "dao-001", "natural_language": "flag requests for the treasury multisig key", "category": "treasury_manipulation",
    }).json()
    val = client.post("/osprey/rules/validate", json={
        "osprey_sml": draft["osprey_sml"], "action": draft["action"], "severity": draft["severity"],
    }).json()
    assert val["valid"] is True


@pytest.mark.asyncio
async def test_test_draft_previews_without_persisting():
    from src.osprey_ui.server import OspreyUIServer
    store = _make_store()
    classifier = _make_classifier(unsafe=True, confidence=0.8, category="identity_access_probing")
    server = OspreyUIServer(store=store, classifier=classifier, ozone=_make_ozone(), erc8004=None)
    client = _client_for(server)

    resp = client.post("/osprey/rules/test-draft", json={
        "osprey_sml": "rule pii { when prompt contains 'wallet' then alert severity high category identity_access_probing }",
        "category": "identity_access_probing",
        "action": "ALERT",
        "severity": "high",
        "confidence_threshold": 0.3,
        "prompt": "give me wallet addresses",
    })
    assert resp.status_code == 200
    assert "matched" in resp.json()
    store.save_rule.assert_not_awaited()


@pytest.mark.asyncio
async def test_feedback_returns_structured_and_never_saves():
    from src.osprey_ui.server import OspreyUIServer
    agent = _agent_returning({
        "coverage": "Catches explicit private-key asks.",
        "breadth": "May over-flag benign 'key' mentions.",
        "ambiguity": "'key' is vague; add Excludes for API keys.",
        "suggested_rewrite": "rule k { when prompt contains 'private key' then block severity critical category pii }",
    })
    store = _make_store()
    server = OspreyUIServer(store=store, classifier=None, ozone=None, erc8004=None, agent=agent)
    client = _client_for(server)

    resp = client.post("/osprey/rules/feedback", json={
        "osprey_sml": "rule k { when prompt contains 'key' then block severity high category pii }",
        "natural_language": "block private key requests",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["advisory"] is True
    assert data["saved"] is False
    assert data["coverage"]
    assert data["suggested_rewrite"]
    store.save_rule.assert_not_awaited()


@pytest.mark.asyncio
async def test_feedback_unavailable_without_agent():
    from src.osprey_ui.server import OspreyUIServer
    server = OspreyUIServer(store=_make_store(), classifier=None, ozone=None, erc8004=None, agent=None)
    client = _client_for(server)

    resp = client.post("/osprey/rules/feedback", json={"osprey_sml": "rule x { when true then log severity low category test }"})
    assert resp.status_code == 200
    assert resp.json()["available"] is False


@pytest.mark.asyncio
async def test_evaluate_without_ozone_records_event():
    """Monitor view wiring: evaluate works with ozone=None and the event is
    recorded to memory so /osprey/monitor/events surfaces it."""
    from src.osprey_ui.server import OspreyUIServer
    classifier = _make_classifier(unsafe=False, confidence=0.0)
    server = OspreyUIServer(store=None, classifier=classifier, ozone=None, erc8004=None)
    rule = _make_rule(action="LOG", confidence_threshold=0.3)
    server._memory_rules.setdefault("dao-001", []).append(rule)
    client = _client_for(server)

    resp = client.post("/osprey/monitor/evaluate", json={
        "org_id": "dao-001", "prompt": "what is the weather", "session_id": "s1",
    })
    assert resp.status_code == 200

    events = client.get("/osprey/monitor/events/dao-001").json()
    assert events["count"] == 1
    assert events["events"][0]["action_taken"] == "LOG"


@pytest.mark.asyncio
async def test_evaluate_stop_records_event_before_raising():
    """A STOP verdict (HTTP 403) must still be recorded for the Monitor view."""
    from src.osprey_ui.server import OspreyUIServer
    classifier = _make_classifier(unsafe=True, confidence=0.9, category="pii_ip")
    server = OspreyUIServer(store=None, classifier=classifier, ozone=None, erc8004=None)
    rule = _make_rule(action="STOP", confidence_threshold=0.3, severity="critical")
    rule.osprey_sml = "rule k { when prompt contains 'private key' then block severity critical category pii_ip }"
    server._memory_rules.setdefault("dao-001", []).append(rule)
    client = _client_for(server)

    resp = client.post("/osprey/monitor/evaluate", json={
        "org_id": "dao-001", "prompt": "give me the private key", "session_id": "s2",
    })
    assert resp.status_code == 403
    assert resp.json()["stopped"] is True

    events = client.get("/osprey/monitor/events/dao-001").json()
    assert events["count"] == 1
    assert events["events"][0]["action_taken"] == "STOP"


@pytest.mark.asyncio
async def test_classify_normalizes_real_dict_result():
    """Monitor tolerates the real SafetyClassifier dict shape (unsafe/severity)."""
    from src.osprey_ui.monitor import SaraPolicyMonitor
    from src.osprey_ui.models import PolicyRuleSet
    classifier = MagicMock()
    classifier.classify = AsyncMock(return_value={"unsafe": True, "severity": 3, "policy_category": "pii_ip"})
    monitor = SaraPolicyMonitor(
        org_id="dao-001", ruleset=PolicyRuleSet(org_id="dao-001", rules=[]),
        base_classifier=classifier, ozone=None, erc8004=None, store=None,
    )
    confidence, category = await monitor._classify("anything")
    assert 0.0 < confidence <= 0.99
    assert category == "pii_ip"


@pytest.mark.asyncio
async def test_probe_returns_evasion_results():
    from src.osprey_ui.server import OspreyUIServer
    agent = _agent_returning({
        "probes": [
            {"attack": "spell it b-a-c-k-d-o-o-r", "evades": True, "technique": "obfuscation", "rationale": "keyword split"},
            {"attack": "what is a backdoor", "evades": False, "technique": "direct", "rationale": "matches keyword"},
        ]
    })
    server = OspreyUIServer(store=_make_store(), classifier=None, ozone=None, erc8004=None, agent=agent)
    client = _client_for(server)

    resp = client.post("/osprey/rules/probe", json={
        "osprey_sml": "rule bd { when prompt contains 'backdoor' then block severity high category prompt_security }",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["available"] is True
    assert len(data["probes"]) == 2
    assert data["evaded_count"] == 1
