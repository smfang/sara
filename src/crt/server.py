"""
CRT HTTP read API — GET routes for campaigns, coverage maps, and reports.

Campaign creation stays CLI-driven (see src/crt/cli.py demo).
The server seeds a completed demo campaign at startup so the UI is
demoable without running the CLI first.

# A.5-full: swap InMemoryCRTStore for ClickHouse-backed store.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from src.crt.aggregator import CoverageAggregator
from src.crt.coordinator import CRTCoordinator
from src.crt.mock_eval import MockEvaluator
from src.crt.models import OrgProfile, OrgType
from src.crt.report import build_report
from src.crt.store import InMemoryCRTStore
from src.sarabox.taxonomy import DAO_TAXONOMY

logger = logging.getLogger(__name__)

_DAO_LEAVES = [leaf["id"] for leaf in DAO_TAXONOMY[:6]]
_FIXTURE_PATH = Path(__file__).parent.parent / "ui" / "crt_sample_report.json"


def _seed_demo(store: InMemoryCRTStore, aggregator: CoverageAggregator) -> None:
    """Populate one completed demo campaign so the UI demos at startup."""
    coordinator = CRTCoordinator(store, aggregator, MockEvaluator())

    orgs = [
        OrgProfile(
            org_id="org-alpha",
            org_type=OrgType.dao_committee,
            display_name="Alpha DAO Committee",
            specialisation_tags=["treasury_manipulation", "governance_red_flags"],
        ),
        OrgProfile(
            org_id="org-beta",
            org_type=OrgType.academic,
            display_name="Beta Academic Lab",
            specialisation_tags=["social_engineering", "information_hazards"],
        ),
        OrgProfile(
            org_id="org-gamma",
            org_type=OrgType.red_team,
            display_name="Gamma Red Team",
            specialisation_tags=["identity_access_probing", "smart_contract_exploitation"],
        ),
    ]

    c = coordinator.create_campaign("sara-v1-dao", _DAO_LEAVES)
    for org in orgs:
        coordinator.enrol_org(c.campaign_id, org)

    for org_id, leaves in {
        "org-alpha": ["treasury_manipulation", "governance_red_flags"],
        "org-beta": ["social_engineering", "information_hazards"],
        "org-gamma": ["identity_access_probing", "smart_contract_exploitation"],
    }.items():
        for leaf in leaves:
            coordinator.submit_finding(c.campaign_id, org_id, leaf)

    coordinator.finalise_campaign(c.campaign_id)


class CRTServer:
    """Read-only HTTP API for the Collaborative Red Teaming MVP.

    Wire into ArenaServer.build_app() via routes.extend(crt_server.routes()).
    Campaign creation is CLI-driven; the UI is read/monitor only.
    """

    def __init__(
        self,
        store: InMemoryCRTStore | None = None,
        aggregator: CoverageAggregator | None = None,
        seed_demo: bool = True,
    ) -> None:
        self._store = store or InMemoryCRTStore()
        self._aggregator = aggregator or CoverageAggregator(self._store)
        if seed_demo and not self._store._campaigns:
            _seed_demo(self._store, self._aggregator)

    def routes(self) -> list[Route]:
        return [
            Route("/crt/campaigns", self._list_campaigns, methods=["GET"]),
            Route("/crt/campaigns/{campaign_id}", self._get_campaign, methods=["GET"]),
            Route("/crt/campaigns/{campaign_id}/coverage", self._get_coverage, methods=["GET"]),
            Route("/crt/campaigns/{campaign_id}/report", self._get_report, methods=["GET"]),
            Route("/crt/fixture", self._get_fixture, methods=["GET"]),
        ]

    async def _list_campaigns(self, request: Request) -> Response:
        out = []
        for c in self._store._campaigns.values():
            cmap = self._aggregator.get_coverage_map(c.campaign_id)
            out.append({
                "campaign_id": c.campaign_id,
                "target_id": c.target_id,
                "status": c.status,
                "participating_orgs_count": cmap.participating_orgs_count,
                "coverage_fraction": cmap.coverage_fraction,
                "started_at": c.started_at.isoformat() if c.started_at else None,
                "completed_at": c.completed_at.isoformat() if c.completed_at else None,
            })
        return JSONResponse({"campaigns": out, "count": len(out)})

    async def _get_campaign(self, request: Request) -> Response:
        cid = request.path_params["campaign_id"]
        c = self._store.get_campaign(cid)
        if c is None:
            return JSONResponse({"error": "campaign not found"}, status_code=404)
        cmap = self._aggregator.get_coverage_map(cid)
        diversity = self._aggregator.diversity_score(cid)
        # Exclude enrolled_org_ids — it directly exposes participant identities
        campaign_public = c.model_dump(mode="json", exclude={"enrolled_org_ids"})
        data = {
            "campaign": campaign_public,
            "coverage_fraction": cmap.coverage_fraction,
            "participating_orgs_count": cmap.participating_orgs_count,
            "diversity_score": diversity,
        }
        assert "org_id" not in json.dumps(data), "PRIVACY BREACH: org_id in campaign response"
        return JSONResponse(data)

    async def _get_coverage(self, request: Request) -> Response:
        cid = request.path_params["campaign_id"]
        c = self._store.get_campaign(cid)
        if c is None:
            return JSONResponse({"error": "campaign not found"}, status_code=404)
        cmap = self._aggregator.get_coverage_map(cid)
        data = cmap.model_dump(mode="json")
        # Privacy guard: enforced at type level; full-JSON check for future-proofing
        assert "org_id" not in json.dumps(data), "PRIVACY BREACH: org_id in coverage response"
        return JSONResponse(data)

    async def _get_report(self, request: Request) -> Response:
        cid = request.path_params["campaign_id"]
        c = self._store.get_campaign(cid)
        if c is None:
            return JSONResponse({"error": "campaign not found"}, status_code=404)
        cmap = self._aggregator.get_coverage_map(cid)
        report = build_report(c, cmap)
        data = report.model_dump(mode="json")
        assert "org_id" not in json.dumps(data), "PRIVACY BREACH: org_id in report response"
        return JSONResponse(data)

    async def _get_fixture(self, request: Request) -> Response:
        """Serve the static fixture fallback so the UI can demo without a live campaign."""
        try:
            data = json.loads(_FIXTURE_PATH.read_text())
        except Exception:
            return JSONResponse({"error": "fixture not found"}, status_code=404)
        return JSONResponse(data)
