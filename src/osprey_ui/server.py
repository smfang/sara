"""
HTTP API routes for Osprey UI Policy Rules and Monitor.

Add to the existing Starlette app. Do not create a new server.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
import time
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from src.osprey_ui.compiler import OspreyRuleCompiler
from src.osprey_ui.dao_defaults import DAO_DEFAULT_RULES
from src.osprey_ui.models import MonitorEvent, PolicyRule, PolicyRuleSet, RuleTestResult
from src.osprey_ui.monitor import SaraPolicyMonitor, SafetyStopException
from src.osprey_ui.store import OspreyUIStore
from src.osprey_ui.vertical_defaults import VERTICAL_PACKS

logger = logging.getLogger(__name__)

API_KEY = os.environ.get("SARA_API_KEY", "")
if not API_KEY:
    import warnings
    warnings.warn(
        "SARA_API_KEY is not set — all Osprey UI endpoints are unauthenticated. "
        "Set SARA_API_KEY in production.",
        stacklevel=1,
    )


def _check_api_key(request: Request) -> bool:
    provided = request.headers.get("x-api-key", "")
    if not API_KEY:
        return True
    return provided == API_KEY


def _403() -> Response:
    return JSONResponse({"error": "forbidden — missing or invalid x-api-key"}, status_code=403)


_VALID_ACTIONS = {"LOG", "ALERT", "STOP", "BLOCK", "QUARANTINE"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _leaf_f1_rows_from_per_leaf(per_leaf: dict) -> list[dict]:
    """Convert tinker_spike per-leaf metrics into Policy-UI F1 rows (OS-05).

    Accepts the ``{leaf: LeafMetrics}`` mapping produced by
    ``src.agent_rl.tinker_spike.evaluate.run_eval`` (LeafMetrics exposes
    precision/recall/f1 properties and tp/fp/fn/tn counts) as well as the
    flattened dict form written by ``eval_result_to_dict``. Rows are sorted by
    F1 ascending so the weakest leaves surface first.
    """
    updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rows: list[dict] = []
    for leaf, m in per_leaf.items():
        get = (lambda k, d=0: m.get(k, d)) if isinstance(m, dict) else (lambda k, d=0: getattr(m, k, d))
        tp, fp, fn, tn = int(get("tp")), int(get("fp")), int(get("fn")), int(get("tn"))
        precision = float(get("precision", tp / (tp + fp) if (tp + fp) else 0.0))
        recall = float(get("recall", tp / (tp + fn) if (tp + fn) else 0.0))
        f1 = float(get("f1", 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0))
        rows.append({
            "category": str(leaf),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "sample_count": tp + fp + fn + tn,
            "updated_at": updated,
        })
    rows.sort(key=lambda r: r["f1"])
    return rows


def _validate_policy_sml(sml: str, action: str, severity: str) -> list[str]:
    """Deterministic, model-free validation for a human-authored PolicyRule.

    Pragmatic schema check appropriate to the ClickHouse PolicyRule path (not the
    full Osprey linter, which governs the agent's raw .sml files). Returns a list
    of human-readable errors; an empty list means the rule may be saved/deployed.
    """
    errors: list[str] = []
    text = (sml or "").strip()
    if not text:
        errors.append("SML is empty — write or compile a rule before saving.")
    else:
        if "rule " not in text:
            errors.append("SML must declare a rule (missing 'rule' keyword).")
        if "when " not in text:
            errors.append("SML must contain a 'when' condition.")
        if "then " not in text:
            errors.append("SML must contain a 'then' action.")
        if text.count("{") != text.count("}"):
            errors.append("Unbalanced braces { } in SML.")
    if (action or "").upper() not in _VALID_ACTIONS:
        errors.append(f"Action '{action}' is invalid (expected one of {sorted(_VALID_ACTIONS)}).")
    if (severity or "").lower() not in _VALID_SEVERITIES:
        errors.append(f"Severity '{severity}' is invalid (expected one of {sorted(_VALID_SEVERITIES)}).")
    return errors


class OspreyUIServer:
    """Server for Osprey UI policy rules and monitor endpoints."""

    def __init__(
        self,
        store: OspreyUIStore | Any | None = None,
        compiler: OspreyRuleCompiler | None = None,
        classifier: Any | None = None,
        ozone: Any | None = None,
        erc8004: Any | None = None,
        arena_store: Any | None = None,
        agent: Any | None = None,
        rl_benchmark: Any | None = None,
    ) -> None:
        self._store = store
        # OS-05 source of record for per-leaf F1: a zero-arg provider (sync or
        # async) returning the RL exit-gate eval — an EvalResult, or a dict /
        # object exposing `per_leaf`. When it yields data the Policy UI shows the
        # same leaf F1 the RL benchmark measured; otherwise we fall back to the
        # arena metrics and then to a monitor-event detection proxy.
        self._rl_benchmark = rl_benchmark
        self._last_f1_source = "none"
        # The frontier-model agent (Sheila) powers NL drafting, AI feedback, and
        # the adversarial probe. When absent the compiler falls back to keywords
        # and the feedback/probe endpoints report that the model is unavailable.
        self._agent = agent
        self._compiler = compiler or OspreyRuleCompiler(agent=agent)
        self._classifier = classifier
        self._ozone = ozone
        self._erc8004 = erc8004
        self._arena_store = arena_store
        # Cache AI feedback by SML hash so repeated requests on an unchanged rule
        # are cheap (the model call is the expensive part).
        self._feedback_cache: dict[str, dict] = {}
        # In-memory fallback when ClickHouse store is not available
        self._memory_rules: dict[str, list[PolicyRule]] = {}
        self._memory_events: list[MonitorEvent] = []
        # In-memory F1 cache when ClickHouse store is not available
        self._memory_f1: list[dict] = []

    def routes(self) -> list[Route]:
        return [
            Route("/osprey/rules/{org_id}", self._list_rules, methods=["GET"]),
            Route("/osprey/rules", self._create_rule, methods=["POST"]),
            # Human rule-authoring (A.5UI_Osprey): draft → validate → preview →
            # AI feedback → adversarial probe, then save through the SAME path.
            Route("/osprey/rules/draft", self._draft_rule, methods=["POST"]),
            Route("/osprey/rules/validate", self._validate_rule, methods=["POST"]),
            Route("/osprey/rules/test-draft", self._test_draft_rule, methods=["POST"]),
            Route("/osprey/rules/feedback", self._rule_feedback, methods=["POST"]),
            Route("/osprey/rules/probe", self._rule_probe, methods=["POST"]),
            Route("/osprey/rules/{rule_id}/test", self._test_rule, methods=["POST"]),
            Route("/osprey/rules/{rule_id}", self._update_rule, methods=["PATCH"]),
            Route("/osprey/rules/{rule_id}", self._delete_rule, methods=["DELETE"]),
            Route("/osprey/monitor/evaluate", self._monitor_evaluate, methods=["POST"]),
            Route("/osprey/monitor/override/{event_id}", self._monitor_override, methods=["POST"]),
            Route("/osprey/monitor/events/{org_id}", self._list_events, methods=["GET"]),
            # OS-04: vertical default rule packs
            Route("/osprey/vertical-defaults", self._list_vertical_packs, methods=["GET"]),
            Route("/osprey/vertical-defaults/{pack}", self._get_vertical_pack, methods=["GET"]),
            Route("/osprey/vertical-defaults/{pack}/install", self._install_vertical_pack, methods=["POST"]),
            # OS-05: per-leaf F1 benchmark scores
            Route("/osprey/benchmark/f1", self._get_f1_stats, methods=["GET"]),
            Route("/osprey/benchmark/f1/refresh", self._refresh_f1_stats, methods=["POST"]),
        ]

    async def _list_rules(self, request: Request) -> Response:
        if not _check_api_key(request):
            return _403()
        org_id = request.path_params["org_id"]
        if self._store is not None and hasattr(self._store, "list_rules_for_org"):
            rules = await self._store.list_rules_for_org(org_id)
        else:
            rules = self._memory_rules.get(org_id, [])
        return JSONResponse({"rules": [r.model_dump(mode="json") for r in rules], "count": len(rules)})

    async def _create_rule(self, request: Request) -> Response:
        if not _check_api_key(request):
            return _403()
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)

        org_id = body.get("org_id", "").strip()
        natural_language = body.get("natural_language", "").strip()
        osprey_sml = (body.get("osprey_sml") or "").strip()
        category = body.get("category", "").strip()
        severity = body.get("severity", "high").strip()
        action = body.get("action", "ALERT").strip()
        created_by = body.get("created_by", "analyst")

        # A human authors either by typing SML directly (raw editor / an edited
        # assisted draft) or by describing it in natural language for the model
        # to compile. Either way the rule lands in the same store via this path.
        if not org_id or not category or not (natural_language or osprey_sml):
            return JSONResponse(
                {"error": "org_id, category, and one of natural_language or osprey_sml are required"},
                status_code=400,
            )

        if osprey_sml:
            rule = PolicyRule(
                org_id=org_id,
                display_name=(body.get("display_name") or natural_language or "Untitled rule")[:80],
                natural_language=natural_language,
                osprey_sml=osprey_sml,
                category=category,
                severity=severity.lower(),
                action=action.upper(),
                confidence_threshold=float(body.get("confidence_threshold", 0.75)),
                created_by=created_by,
            )
        else:
            rule = await self._compiler.compile(
                org_id=org_id,
                natural_language=natural_language,
                category=category,
                severity=severity,
                created_by=created_by,
            )
            rule.action = action.upper()

        # Validate-gate: a rule that fails deterministic validation is never
        # persisted — identical gate for assisted and raw-SML authoring.
        errors = _validate_policy_sml(rule.osprey_sml, rule.action, rule.severity)
        if errors:
            return JSONResponse({"error": "validation failed", "errors": errors}, status_code=400)

        if self._store is not None and hasattr(self._store, "save_rule"):
            await self._store.save_rule(rule)
        else:
            self._memory_rules.setdefault(org_id, []).append(rule)

        # ERC8004 attestation on rule create
        if self._erc8004 is not None:
            try:
                result_hash = hashlib.sha3_256(rule.model_dump_json().encode()).hexdigest()
                record = await self._erc8004.record_evaluation_result(
                    subject=rule.rule_id,
                    label=f"rule:{rule.action}",
                    metadata={"result_hash": result_hash, "org_id": org_id},
                )
                if record:
                    rule.erc8004_tx_hash = record.tx_hash
                    if self._store is not None and hasattr(self._store, "save_rule"):
                        await self._store.save_rule(rule)
            except Exception as exc:
                logger.warning("ERC8004 attestation failed for rule %s: %s", rule.rule_id, exc)

        return JSONResponse(rule.model_dump(mode="json"), status_code=201)

    # ------------------------------------------------------------------
    # Human rule-authoring: draft / validate / preview / feedback / probe
    # ------------------------------------------------------------------

    async def _draft_rule(self, request: Request) -> Response:
        """Compile NL → SML for the assisted authoring mode WITHOUT persisting.

        The model drafts; the human reviews/edits the returned SML and only then
        calls POST /osprey/rules to save. No store write happens here.
        """
        if not _check_api_key(request):
            return _403()
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)

        org_id = body.get("org_id", "").strip()
        natural_language = body.get("natural_language", "").strip()
        category = body.get("category", "").strip()
        severity = body.get("severity", "high").strip()
        action = body.get("action", "ALERT").strip()
        created_by = body.get("created_by", "analyst")

        if not org_id or not natural_language or not category:
            return JSONResponse(
                {"error": "org_id, natural_language, and category are required"},
                status_code=400,
            )

        rule = await self._compiler.compile(
            org_id=org_id,
            natural_language=natural_language,
            category=category,
            severity=severity,
            created_by=created_by,
        )
        if action:
            rule.action = action.upper()

        payload = rule.model_dump(mode="json")
        payload["persisted"] = False
        payload["validation"] = _validate_policy_sml(rule.osprey_sml, rule.action, rule.severity)
        return JSONResponse(payload)

    async def _validate_rule(self, request: Request) -> Response:
        """Deterministically validate a draft rule without saving it."""
        if not _check_api_key(request):
            return _403()
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)

        sml = (body.get("osprey_sml") or "").strip()
        action = body.get("action", "ALERT")
        severity = body.get("severity", "high")
        errors = _validate_policy_sml(sml, action, severity)
        return JSONResponse({"valid": not errors, "errors": errors})

    async def _test_draft_rule(self, request: Request) -> Response:
        """Preview an UNSAVED rule against a sample prompt (no persistence)."""
        if not _check_api_key(request):
            return _403()
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)

        prompt = (body.get("prompt") or "").strip()
        sml = (body.get("osprey_sml") or "").strip()
        if not prompt or not sml:
            return JSONResponse({"error": "prompt and osprey_sml are required"}, status_code=400)
        if self._classifier is None:
            return JSONResponse({"error": "classifier not configured"}, status_code=503)

        draft = PolicyRule(
            org_id=body.get("org_id", "draft").strip() or "draft",
            display_name=(body.get("display_name") or "Draft rule")[:80],
            natural_language=body.get("natural_language", ""),
            osprey_sml=sml,
            category=body.get("category", "draft"),
            severity=str(body.get("severity", "high")).lower(),
            action=str(body.get("action", "ALERT")).upper(),
            confidence_threshold=float(body.get("confidence_threshold", 0.75)),
            created_by=body.get("created_by", "analyst"),
        )
        monitor = SaraPolicyMonitor(
            org_id=draft.org_id,
            ruleset=PolicyRuleSet(org_id=draft.org_id, rules=[draft]),
            base_classifier=self._classifier,
            ozone=self._ozone,
            erc8004=None,
            store=None,
        )
        result = await monitor.test_rule(prompt, draft)
        return JSONResponse(result.model_dump(mode="json"))

    async def _rule_feedback(self, request: Request) -> Response:
        """⭐ Qualitative AI review of the rule the human entered (advisory only).

        Sends the rule text to the configured frontier model and returns
        coverage / breadth / ambiguity notes plus a suggested rewrite. Never
        saves anything; deterministic validation + human approval still gate
        deploy. Cached by rule hash so repeat requests are cheap.
        """
        if not _check_api_key(request):
            return _403()
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)

        sml = (body.get("osprey_sml") or "").strip()
        natural_language = body.get("natural_language", "").strip()
        if not sml:
            return JSONResponse({"error": "osprey_sml is required"}, status_code=400)

        if self._agent is None:
            return JSONResponse({
                "available": False,
                "advisory": True,
                "saved": False,
                "note": "Frontier model not configured — feedback unavailable.",
            })

        cache_key = hashlib.sha3_256(f"{sml}\n{natural_language}".encode()).hexdigest()
        if cache_key in self._feedback_cache:
            cached = dict(self._feedback_cache[cache_key])
            cached["cached"] = True
            return JSONResponse(cached)

        user_msg = (
            "You are reviewing a draft Osprey safety rule authored by a human operator. "
            "Give a concise, qualitative review. Respond with ONLY valid JSON:\n"
            '{"coverage": "...", "breadth": "...", "ambiguity": "...", "suggested_rewrite": "<improved .sml or empty>"}\n\n'
            "- coverage: what this rule catches vs. likely misses.\n"
            "- breadth: false-positive risk (benign content it may flag) and gaps.\n"
            "- ambiguity: vague terms an attacker could exploit; concrete Includes/Excludes suggestions.\n"
            "- suggested_rewrite: an improved .sml draft, or an empty string if the rule is already good.\n\n"
            f"Intent (natural language): {natural_language or '(none provided)'}\n"
            f"Rule SML:\n{sml}\n"
        )
        feedback = await self._call_agent_json(user_msg, mode="judge")
        result = {
            "available": True,
            "advisory": True,
            "saved": False,
            "coverage": feedback.get("coverage", ""),
            "breadth": feedback.get("breadth", ""),
            "ambiguity": feedback.get("ambiguity", ""),
            "suggested_rewrite": feedback.get("suggested_rewrite", ""),
        }
        if "_raw" in feedback:
            result["note"] = "Model response was not structured JSON; showing raw text."
            result["coverage"] = result["coverage"] or feedback["_raw"]
        self._feedback_cache[cache_key] = result
        return JSONResponse(result)

    async def _rule_probe(self, request: Request) -> Response:
        """Adversarial probe: ask Sheila (red-team mode) for evasion attempts
        against the rule and report which it believes would slip through.
        Advisory only — never saves."""
        if not _check_api_key(request):
            return _403()
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)

        sml = (body.get("osprey_sml") or "").strip()
        if not sml:
            return JSONResponse({"error": "osprey_sml is required"}, status_code=400)
        if self._agent is None:
            return JSONResponse({"available": False, "advisory": True, "probes": []})

        n = max(1, min(int(body.get("sample_count", 5)), 8))
        natural_language = body.get("natural_language", "").strip()
        user_msg = (
            f"Generate {n} adversarial prompts that attempt to EVADE the safety rule below, "
            "using varied techniques (paraphrase, encoding, role-play, language switch, etc.). "
            "For each, judge whether it would slip past this specific rule. "
            "Respond with ONLY valid JSON: "
            '{"probes": [{"attack": "...", "evades": true, "technique": "...", "rationale": "..."}]}\n\n'
            f"Intent: {natural_language or '(none provided)'}\n"
            f"Rule SML:\n{sml}\n"
        )
        parsed = await self._call_agent_json(user_msg, mode="redteam")
        probes = parsed.get("probes", [])
        if not isinstance(probes, list):
            probes = []
        return JSONResponse({
            "available": True,
            "advisory": True,
            "probes": probes,
            "evaded_count": sum(1 for p in probes if isinstance(p, dict) and p.get("evades")),
        })

    async def _call_agent_json(self, user_msg: str, mode: str) -> dict:
        """Call the agent and parse a JSON object from its reply. On any failure
        returns {"_raw": <text or error>} so callers can degrade gracefully."""
        try:
            raw = await self._agent.chat(
                user_message=user_msg,
                session_id=f"osprey-ui-{os.urandom(4).hex()}",
                mode=mode,
            )
        except Exception as exc:
            logger.warning("Agent call failed for Osprey UI (%s)", exc)
            return {"_raw": f"Model call failed: {exc}"}

        text = (raw or "").strip()
        if text.startswith("```"):
            # strip a ```json ... ``` fence
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else {"_raw": text}
        except json.JSONDecodeError:
            return {"_raw": text}

    async def _test_rule(self, request: Request) -> Response:
        if not _check_api_key(request):
            return _403()
        rule_id = request.path_params["rule_id"]
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)

        prompt = body.get("prompt", "").strip()
        if not prompt:
            return JSONResponse({"error": "prompt is required"}, status_code=400)

        if self._store is not None and hasattr(self._store, "get_rule"):
            rule = await self._store.get_rule(rule_id)
        else:
            rule = None
            for rules in self._memory_rules.values():
                for r in rules:
                    if r.rule_id == rule_id:
                        rule = r
                        break
                if rule:
                    break
        if not rule:
            return JSONResponse({"error": "rule not found"}, status_code=404)

        if self._classifier is None:
            return JSONResponse({"error": "classifier not configured"}, status_code=503)

        monitor = SaraPolicyMonitor(
            org_id=rule.org_id,
            ruleset=PolicyRuleSet(org_id=rule.org_id, rules=[rule]),
            base_classifier=self._classifier,
            ozone=self._ozone,
            erc8004=self._erc8004,
            store=None,
        )
        result = await monitor.test_rule(prompt, rule)
        return JSONResponse(result.model_dump(mode="json"))

    async def _update_rule(self, request: Request) -> Response:
        if not _check_api_key(request):
            return _403()
        rule_id = request.path_params["rule_id"]
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)

        if self._store is not None and hasattr(self._store, "get_rule"):
            rule = await self._store.get_rule(rule_id)
        else:
            rule = None
            for rules in self._memory_rules.values():
                for r in rules:
                    if r.rule_id == rule_id:
                        rule = r
                        break
                if rule:
                    break
        if not rule:
            return JSONResponse({"error": "rule not found"}, status_code=404)

        # Update mutable fields
        if "confidence_threshold" in body:
            rule.confidence_threshold = float(body["confidence_threshold"])
        if "action" in body:
            rule.action = str(body["action"]).upper()
        if "severity" in body:
            rule.severity = str(body["severity"]).lower()
        if "enabled" in body:
            rule.enabled = bool(body["enabled"])

        rule.version += 1
        if self._store is not None and hasattr(self._store, "update_rule"):
            await self._store.update_rule(rule)

        # ERC8004 attestation on rule change
        if self._erc8004 is not None:
            try:
                result_hash = hashlib.sha3_256(rule.model_dump_json().encode()).hexdigest()
                await self._erc8004.record_evaluation_result(
                    subject=rule.rule_id,
                    label=f"rule_updated:v{rule.version}",
                    metadata={"result_hash": result_hash, "org_id": rule.org_id},
                )
            except Exception as exc:
                logger.warning("ERC8004 attestation failed for rule update %s: %s", rule.rule_id, exc)

        return JSONResponse(rule.model_dump(mode="json"))

    async def _delete_rule(self, request: Request) -> Response:
        if not _check_api_key(request):
            return _403()
        rule_id = request.path_params["rule_id"]
        if self._store is not None and hasattr(self._store, "get_rule"):
            rule = await self._store.get_rule(rule_id)
        else:
            rule = None
            for rules in self._memory_rules.values():
                for r in rules:
                    if r.rule_id == rule_id:
                        rule = r
                        break
                if rule:
                    break
        if not rule:
            return JSONResponse({"error": "rule not found"}, status_code=404)

        rule.enabled = False
        rule.version += 1
        if self._store is not None and hasattr(self._store, "update_rule"):
            await self._store.update_rule(rule)
        return JSONResponse({"status": "disabled", "rule_id": rule_id})

    async def _monitor_evaluate(self, request: Request) -> Response:
        if not _check_api_key(request):
            return _403()
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)

        org_id = body.get("org_id", "").strip()
        prompt = body.get("prompt", "").strip()
        session_id = body.get("session_id", "").strip() or f"sess-{int(time.time() * 1000)}"

        if not org_id or not prompt:
            return JSONResponse({"error": "org_id and prompt are required"}, status_code=400)

        # Ozone (label enforcement) is optional — the monitor guards its own
        # ozone calls and still raises on STOP without it. Only the classifier
        # is required to evaluate, so dev servers without Ozone can still emit
        # MonitorEvents for the Monitor view.
        if self._classifier is None:
            return JSONResponse({"error": "classifier not configured"}, status_code=503)

        if self._store is not None and hasattr(self._store, "list_rules_for_org"):
            rules = await self._store.list_rules_for_org(org_id)
        else:
            rules = self._memory_rules.get(org_id, [])
        active_rules = [r for r in rules if r.enabled]
        ruleset = PolicyRuleSet(org_id=org_id, rules=active_rules)

        monitor = SaraPolicyMonitor(
            org_id=org_id,
            ruleset=ruleset,
            base_classifier=self._classifier,
            ozone=self._ozone,
            erc8004=self._erc8004,
            store=self._store,
        )

        try:
            event = await monitor.evaluate(prompt, session_id)
            self._record_event(event)
            return JSONResponse(event.model_dump(mode="json"))
        except SafetyStopException as exc:
            # STOP raises before the monitor's own persist step, so record here
            # too — the Monitor view must show blocked events, not just allowed ones.
            self._record_event(exc.event)
            return JSONResponse({
                "stopped": True,
                "event": exc.event.model_dump(mode="json"),
            }, status_code=403)

    def _record_event(self, event: Any) -> None:
        """Keep a MonitorEvent visible to the Monitor view.

        When the backing store implements monitor-event persistence the monitor
        already wrote it there. When it doesn't (e.g. ArenaStore in the dev
        arena), fall back to the server's in-memory list that _list_events reads,
        newest-first and capped, so the Monitor tab still surfaces live events.
        """
        if self._store is not None and hasattr(self._store, "list_monitor_events"):
            return
        self._memory_events.insert(0, event)
        del self._memory_events[1000:]

    async def _monitor_override(self, request: Request) -> Response:
        if not _check_api_key(request):
            return _403()
        event_id = request.path_params["event_id"]
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)

        operator_id = body.get("operator_id", "").strip()
        if not operator_id:
            return JSONResponse({"error": "operator_id is required"}, status_code=400)

        # We need a monitor instance to call override; use a minimal one
        monitor = SaraPolicyMonitor(
            org_id="",
            ruleset=PolicyRuleSet(org_id="", rules=[]),
            base_classifier=self._classifier,
            ozone=self._ozone,
            erc8004=self._erc8004,
            store=self._store,
        )
        ok = monitor.override(event_id, operator_id)
        return JSONResponse({"overridden": ok, "event_id": event_id})

    async def _list_events(self, request: Request) -> Response:
        if not _check_api_key(request):
            return _403()
        org_id = request.path_params["org_id"]
        action = request.query_params.get("action") or None
        rule_id = request.query_params.get("rule_id") or None
        from_ts = request.query_params.get("from") or None
        to_ts = request.query_params.get("to") or None
        limit = min(int(request.query_params.get("limit", "100")), 1000)

        if self._store is not None and hasattr(self._store, "list_monitor_events"):
            events = await self._store.list_monitor_events(
                org_id=org_id,
                action=action,
                rule_id=rule_id,
                from_ts=from_ts,
                to_ts=to_ts,
                limit=limit,
            )
        else:
            events = [e for e in self._memory_events if e.org_id == org_id]
            if action:
                events = [e for e in events if e.action_taken == action]
            if rule_id:
                events = [e for e in events if e.matched_rule_id == rule_id]
            events = events[:limit]
        return JSONResponse({
            "events": [e.model_dump(mode="json") for e in events],
            "count": len(events),
        })

    # ------------------------------------------------------------------
    # OS-04: Vertical default rule packs
    # ------------------------------------------------------------------

    async def _list_vertical_packs(self, request: Request) -> Response:
        if not _check_api_key(request):
            return _403()
        packs = [
            {
                "pack": name,
                "rule_count": len(rules),
                "categories": list({r.category for r in rules}),
            }
            for name, rules in VERTICAL_PACKS.items()
        ]
        return JSONResponse({"packs": packs})

    async def _get_vertical_pack(self, request: Request) -> Response:
        if not _check_api_key(request):
            return _403()
        pack_name = request.path_params["pack"]
        rules = VERTICAL_PACKS.get(pack_name)
        if rules is None:
            return JSONResponse(
                {"error": f"unknown pack '{pack_name}'. Available: {list(VERTICAL_PACKS)}"}, status_code=404
            )
        return JSONResponse({
            "pack": pack_name,
            "rules": [r.model_dump(mode="json") for r in rules],
            "count": len(rules),
        })

    async def _install_vertical_pack(self, request: Request) -> Response:
        """Install a vertical rule pack into an org's ruleset (OS-04)."""
        if not _check_api_key(request):
            return _403()
        pack_name = request.path_params["pack"]
        rules = VERTICAL_PACKS.get(pack_name)
        if rules is None:
            return JSONResponse(
                {"error": f"unknown pack '{pack_name}'. Available: {list(VERTICAL_PACKS)}"}, status_code=404
            )

        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)

        org_id = body.get("org_id", "").strip()
        if not org_id:
            return JSONResponse({"error": "org_id is required"}, status_code=400)

        installed: list[dict] = []
        for template in rules:
            rule = template.model_copy(update={"org_id": org_id, "created_by": body.get("created_by", "system")})
            if self._store is not None and hasattr(self._store, "save_rule"):
                await self._store.save_rule(rule)
            else:
                self._memory_rules.setdefault(org_id, []).append(rule)
            installed.append(rule.model_dump(mode="json"))

        return JSONResponse({"installed": installed, "count": len(installed)}, status_code=201)

    # ------------------------------------------------------------------
    # OS-05: Per-leaf F1 benchmark scores
    # ------------------------------------------------------------------

    async def _get_f1_stats(self, request: Request) -> Response:
        """Return per-taxonomy-leaf F1 scores so rule authors see Sara's weak spots."""
        if not _check_api_key(request):
            return _403()

        if self._store is not None and hasattr(self._store, "get_leaf_f1_stats"):
            stats = await self._store.get_leaf_f1_stats()
        else:
            stats = self._memory_f1

        return JSONResponse({
            "leaf_f1": stats,
            "count": len(stats),
            "note": (
                "f1 < 0.6 indicates categories where Sara's classifier misses attacks most often. "
                "Tighten or add rules for those leaves."
            ),
        })

    async def _refresh_f1_stats(self, request: Request) -> Response:
        """
        Recompute per-leaf F1 from arena attack history and rule performance metrics.

        Uses rule_performance_metrics (TP/FP) and attack_history (sample counts)
        from the arena store when available; falls back to monitor events.
        """
        if not _check_api_key(request):
            return _403()

        stats = await self._compute_leaf_f1()
        if not stats:
            return JSONResponse({"refreshed": 0, "message": "no benchmark data available yet"})
        source = self._last_f1_source

        for s in stats:
            if self._store is not None and hasattr(self._store, "upsert_leaf_f1"):
                await self._store.upsert_leaf_f1(
                    category=s["category"],
                    precision_val=s["precision"],
                    recall_val=s["recall"],
                    f1_score=s["f1"],
                    sample_count=s["sample_count"],
                )
            else:
                existing = {e["category"] for e in self._memory_f1}
                if s["category"] in existing:
                    self._memory_f1 = [e if e["category"] != s["category"] else s for e in self._memory_f1]
                else:
                    self._memory_f1.append(s)

        return JSONResponse({"refreshed": len(stats), "leaf_f1": stats, "source": source})

    async def _compute_leaf_f1(self) -> list[dict]:
        """
        Derive per-leaf F1 scores.

        Priority (first source that yields data wins):
        1. RL exit-gate benchmark — true per-leaf F1 from tinker_spike eval (OS-05)
        2. arena.rule_performance_metrics (TP + FP per category label)
        3. arena.attack_history (recall proxy from detection rate)
        4. osprey_ui.monitor_events (ALERT/STOP as TP proxy when arena unavailable)
        """
        # --- 1. RL benchmark: the measured leaf F1 rule authors actually want ---
        if self._rl_benchmark is not None:
            rows = await self._compute_f1_from_rl_benchmark()
            if rows:
                self._last_f1_source = "rl_benchmark"
                return rows

        # --- 2/3. arena store ---
        if self._arena_store is not None:
            rows = await self._compute_f1_from_arena()
            if rows:
                self._last_f1_source = "arena"
                return rows

        # --- 4. fall back to monitor events ---
        rows = await self._compute_f1_from_monitor_events()
        self._last_f1_source = "monitor_events" if rows else "none"
        return rows

    async def _compute_f1_from_rl_benchmark(self) -> list[dict]:
        """Per-leaf F1 straight from the RL exit-gate benchmark (tinker_spike).

        ``self._rl_benchmark`` is a zero-arg provider (sync or async) returning
        the eval — an EvalResult, or a dict/object exposing ``per_leaf``. This is
        the OS-05 source of record: the same leaf F1 the RL eval gate computes,
        so rule authors see the classifier's measured weak spots rather than a
        runtime detection proxy.
        """
        provider = self._rl_benchmark
        try:
            result = provider() if callable(provider) else provider
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:
            logger.warning("RL benchmark provider failed: %s", exc)
            return []
        if result is None:
            return []
        per_leaf = getattr(result, "per_leaf", None)
        if per_leaf is None and isinstance(result, dict):
            per_leaf = result.get("per_leaf")
        if not per_leaf:
            return []
        return _leaf_f1_rows_from_per_leaf(per_leaf)

    async def _compute_f1_from_arena(self) -> list[dict]:
        """Compute F1 from arena rule_performance_metrics + attack_history."""
        try:
            # Per-category TP/FP from rule_performance_metrics
            metrics_sql = """
                SELECT label, sum(confirmed_violations), sum(false_positives), sum(total_enforcements)
                FROM arena.rule_performance_metrics FINAL
                GROUP BY label
            """
            metrics_resp = await self._arena_store._ch.query(metrics_sql)
            perf: dict[str, dict] = {}
            for row in metrics_resp.result_rows:  # type: ignore
                cat = str(row[0])
                perf[cat] = {
                    "tp": int(row[1]),
                    "fp": int(row[2]),
                    "total_enforcements": int(row[3]),
                }

            # Per-category attack counts from attack_history (FN proxy)
            hist_sql = """
                SELECT category, count() as attempts
                FROM arena.attack_history FINAL
                GROUP BY category
            """
            hist_resp = await self._arena_store._ch.query(hist_sql)
            hist: dict[str, int] = {}
            for row in hist_resp.result_rows:  # type: ignore
                hist[str(row[0])] = int(row[1])

            all_cats = set(perf) | set(hist)
            results = []
            for cat in sorted(all_cats):
                tp = perf.get(cat, {}).get("tp", 0)
                fp = perf.get(cat, {}).get("fp", 0)
                attacks = hist.get(cat, 0)
                fn = max(0, attacks - tp)
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
                f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
                results.append({
                    "category": cat,
                    "precision": round(precision, 4),
                    "recall": round(recall, 4),
                    "f1": round(f1, 4),
                    "sample_count": max(tp + fp, attacks),
                    "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })
            return results
        except Exception as exc:
            logger.warning("Arena F1 computation failed: %s", exc)
            return []

    async def _compute_f1_from_monitor_events(self) -> list[dict]:
        """Compute detection-rate F1 proxy from monitor events (no arena store)."""
        if self._store is not None and hasattr(self._store, "list_monitor_events"):
            events = await self._store.list_monitor_events(org_id="", limit=10000)
        else:
            events = self._memory_events

        if not events:
            return []

        # Group by matched rule category (from memory_rules for lookup)
        cat_tp: dict[str, int] = {}
        cat_total: dict[str, int] = {}

        for e in events:
            if e.matched_rule_id is None:
                continue
            # Look up rule to get category
            cat = self._get_rule_category(e.matched_rule_id)
            if cat is None:
                continue
            cat_total[cat] = cat_total.get(cat, 0) + 1
            if e.action_taken in ("ALERT", "STOP"):
                cat_tp[cat] = cat_tp.get(cat, 0) + 1

        results = []
        for cat in sorted(cat_total):
            tp = cat_tp.get(cat, 0)
            total = cat_total[cat]
            # Without FP/FN data, use detection rate as recall proxy
            recall = tp / total if total > 0 else 0.0
            precision = recall  # symmetric assumption when no FP data
            f1 = recall  # simplification: F1 ≈ recall when precision ≈ recall
            results.append({
                "category": cat,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "sample_count": total,
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
        return results

    def _get_rule_category(self, rule_id: str) -> str | None:
        """Look up a rule's category from in-memory store (best-effort)."""
        for rules in self._memory_rules.values():
            for r in rules:
                if r.rule_id == rule_id:
                    return r.category
        return None
