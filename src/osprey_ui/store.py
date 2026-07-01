"""
ClickHouse-backed persistent store for Osprey UI.

Follows src/arena/store.py pattern exactly.
"""

from __future__ import annotations

import logging
from typing import Any

from src.clickhouse.clickhouse import Clickhouse
from src.osprey_ui.models import MonitorEvent, PolicyRule

logger = logging.getLogger(__name__)

OSPREY_UI_DDL = [
    "CREATE DATABASE IF NOT EXISTS osprey_ui",
    """
    CREATE TABLE IF NOT EXISTS osprey_ui.leaf_f1_cache (
        category       String,
        precision_val  Float32 DEFAULT 0,
        recall_val     Float32 DEFAULT 0,
        f1_score       Float32 DEFAULT 0,
        sample_count   UInt32 DEFAULT 0,
        updated_at     DateTime64(3) DEFAULT now()
    ) ENGINE = ReplacingMergeTree(updated_at)
      ORDER BY category
    """,
    """
    CREATE TABLE IF NOT EXISTS osprey_ui.policy_rules (
        rule_id        String,
        org_id         String,
        display_name   String,
        natural_language String,
        osprey_sml     String,
        category       String,
        severity       String,
        action         String,
        confidence_threshold Float32,
        enabled        Bool DEFAULT true,
        version        UInt32,
        created_at     DateTime64(3) DEFAULT now(),
        created_by     String,
        erc8004_tx_hash String DEFAULT ''
    ) ENGINE = MergeTree()
      ORDER BY (org_id, created_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS osprey_ui.monitor_events (
        event_id       String,
        org_id         String,
        session_id     String,
        prompt_hash    String,
        matched_rule_id Nullable(String),
        action_taken   String,
        confidence     Float32,
        timestamp      DateTime64(3) DEFAULT now(),
        erc8004_tx_hash String DEFAULT ''
    ) ENGINE = MergeTree()
      ORDER BY (org_id, timestamp)
    """,
]


class OspreyUIStore:
    """Persistent store backed by ClickHouse for Osprey UI."""

    def __init__(self, clickhouse: Clickhouse) -> None:
        self._ch = clickhouse

    async def initialize(self) -> None:
        """Create osprey_ui database and tables if they don't exist."""
        for ddl in OSPREY_UI_DDL:
            try:
                await self._ch.query(ddl.strip())
            except Exception:
                logger.warning("DDL may already exist: %s", ddl[:80], exc_info=True)
        logger.info("Osprey UI ClickHouse tables initialized")

    # ------------------------------------------------------------------
    # Policy Rules
    # ------------------------------------------------------------------

    async def save_rule(self, rule: PolicyRule) -> None:
        sql = f"""
            INSERT INTO osprey_ui.policy_rules VALUES (
                '{_esc(rule.rule_id)}',
                '{_esc(rule.org_id)}',
                '{_esc(rule.display_name)}',
                '{_esc(rule.natural_language)}',
                '{_esc(rule.osprey_sml)}',
                '{_esc(rule.category)}',
                '{_esc(rule.severity)}',
                '{_esc(rule.action)}',
                {rule.confidence_threshold},
                {1 if rule.enabled else 0},
                {rule.version},
                {int(rule.created_at.timestamp() * 1000)},
                '{_esc(rule.created_by)}',
                '{_esc(rule.erc8004_tx_hash)}'
            )
        """
        await self._ch.query(sql)

    async def get_rule(self, rule_id: str) -> PolicyRule | None:
        sql = f"""
            SELECT * FROM osprey_ui.policy_rules
            WHERE rule_id = '{_esc(rule_id)}'
            ORDER BY version DESC
            LIMIT 1
        """
        resp = await self._ch.query(sql)
        rows = resp.result_rows  # type: ignore
        if not rows:
            return None
        return _row_to_policy_rule(rows[0])

    async def list_rules_for_org(self, org_id: str) -> list[PolicyRule]:
        sql = f"""
            SELECT * FROM osprey_ui.policy_rules
            WHERE org_id = '{_esc(org_id)}'
            ORDER BY created_at DESC
        """
        resp = await self._ch.query(sql)
        # Deduplicate by rule_id, keeping latest version
        seen: set[str] = set()
        rules: list[PolicyRule] = []
        for row in resp.result_rows:  # type: ignore
            r = _row_to_policy_rule(row)
            if r.rule_id not in seen:
                seen.add(r.rule_id)
                rules.append(r)
        return rules

    async def update_rule(self, rule: PolicyRule) -> None:
        await self.save_rule(rule)

    # ------------------------------------------------------------------
    # Monitor Events
    # ------------------------------------------------------------------

    async def save_monitor_event(self, event: MonitorEvent) -> None:
        matched = f"'{_esc(event.matched_rule_id)}'" if event.matched_rule_id else "NULL"
        sql = f"""
            INSERT INTO osprey_ui.monitor_events VALUES (
                '{_esc(event.event_id)}',
                '{_esc(event.org_id)}',
                '{_esc(event.session_id)}',
                '{_esc(event.prompt_hash)}',
                {matched},
                '{_esc(event.action_taken)}',
                {event.confidence},
                {int(event.timestamp.timestamp() * 1000)},
                '{_esc(event.erc8004_tx_hash)}'
            )
        """
        await self._ch.query(sql)

    async def list_monitor_events(
        self,
        org_id: str | None,
        action: str | None = None,
        rule_id: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
        limit: int = 100,
    ) -> list[MonitorEvent]:
        # org_id=None or "" means cross-org scan (used by F1 refresh)
        conditions = [] if not org_id else [f"org_id = '{_esc(org_id)}'"]
        if action:
            conditions.append(f"action_taken = '{_esc(action)}'")
        if rule_id:
            conditions.append(f"matched_rule_id = '{_esc(rule_id)}'")
        if from_ts:
            conditions.append(f"timestamp >= '{_esc(from_ts)}'")
        if to_ts:
            conditions.append(f"timestamp <= '{_esc(to_ts)}'")
        where = " AND ".join(conditions)
        sql = f"""
            SELECT * FROM osprey_ui.monitor_events
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT {limit}
        """
        resp = await self._ch.query(sql)
        return [_row_to_monitor_event(r) for r in resp.result_rows]  # type: ignore

    async def get_monitor_event(self, event_id: str) -> MonitorEvent | None:
        sql = f"""
            SELECT * FROM osprey_ui.monitor_events
            WHERE event_id = '{_esc(event_id)}'
            ORDER BY timestamp DESC
            LIMIT 1
        """
        resp = await self._ch.query(sql)
        rows = resp.result_rows  # type: ignore
        if not rows:
            return None
        return _row_to_monitor_event(rows[0])

    # ------------------------------------------------------------------
    # OS-05: Leaf F1 cache
    # ------------------------------------------------------------------

    async def get_leaf_f1_stats(self) -> list[dict]:
        """Return cached per-category F1 scores for the Policy UI (OS-05)."""
        sql = """
            SELECT category, precision_val, recall_val, f1_score, sample_count, updated_at
            FROM osprey_ui.leaf_f1_cache FINAL
            ORDER BY f1_score ASC
        """
        try:
            resp = await self._ch.query(sql)
            return [
                {
                    "category": str(row[0]),
                    "precision": float(row[1]),
                    "recall": float(row[2]),
                    "f1": float(row[3]),
                    "sample_count": int(row[4]),
                    "updated_at": str(row[5]),
                }
                for row in resp.result_rows  # type: ignore
            ]
        except Exception:
            return []

    async def upsert_leaf_f1(
        self,
        category: str,
        precision_val: float,
        recall_val: float,
        f1_score: float,
        sample_count: int,
    ) -> None:
        """Write or update F1 stats for one taxonomy leaf."""
        import time
        sql = f"""
            INSERT INTO osprey_ui.leaf_f1_cache VALUES (
                '{_esc(category)}',
                {precision_val},
                {recall_val},
                {f1_score},
                {sample_count},
                {int(time.time() * 1000)}
            )
        """
        await self._ch.query(sql)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _esc(s: str) -> str:
    """Escape for ClickHouse SQL string literals."""
    return s.replace("\\", "\\\\").replace("'", "\\'")


def _row_to_policy_rule(row: tuple) -> PolicyRule:
    from datetime import datetime
    created_at = datetime.utcfromtimestamp(int(row[11]) / 1000) if len(row) > 11 and row[11] else datetime.utcnow()
    return PolicyRule(
        rule_id=str(row[0]),
        org_id=str(row[1]),
        display_name=str(row[2]),
        natural_language=str(row[3]),
        osprey_sml=str(row[4]),
        category=str(row[5]),
        severity=str(row[6]),
        action=str(row[7]),
        confidence_threshold=float(row[8]),
        enabled=bool(row[9]),
        version=int(row[10]),
        created_at=created_at,
        created_by=str(row[12]) if len(row) > 12 else "",
        erc8004_tx_hash=str(row[13]) if len(row) > 13 else "",
    )


def _row_to_monitor_event(row: tuple) -> MonitorEvent:
    from datetime import datetime
    # DDL column order (9 cols, indices 0-8):
    # event_id(0) org_id(1) session_id(2) prompt_hash(3) matched_rule_id(4)
    # action_taken(5) confidence(6) timestamp(7) erc8004_tx_hash(8)
    ts = datetime.utcfromtimestamp(int(row[7]) / 1000) if len(row) > 7 and row[7] else datetime.utcnow()
    return MonitorEvent(
        event_id=str(row[0]),
        org_id=str(row[1]),
        session_id=str(row[2]),
        prompt_hash=str(row[3]),
        matched_rule_id=str(row[4]) if row[4] is not None else None,
        action_taken=str(row[5]),
        confidence=float(row[6]),
        timestamp=ts,
        erc8004_tx_hash=str(row[8]) if len(row) > 8 else "",
    )
