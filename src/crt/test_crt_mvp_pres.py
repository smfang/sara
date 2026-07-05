"""
CRT MVP — presentation-slice tests.

Covers the Monday narrative: N orgs coordinate on one DAO target, org C is
scoped for a leaf it has NO local data for, and the FEDERATION covers it.
Also exercises the FederatedIncidentStore privacy surface and the credit split.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from click.testing import CliRunner

from src.crt.aggregator import CoverageAggregator
from src.crt.cli import demo
from src.crt.coordinator import CRTCoordinator
from src.crt.coverage_view import build_coverage_map
from src.crt.mock_eval import MockEvaluator
from src.crt.models import CoverageMap, OrgProfile, OrgType
from src.crt.store import InMemoryCRTStore
from src.crt.store_incidents import FederatedIncidentStore

DAO_LEAVES = [
    "identity_access_probing",
    "treasury_manipulation",
    "governance_red_flags",
    "social_engineering",
    "smart_contract_exploitation",
    "information_hazards",
]


def _stack():
    store = InMemoryCRTStore()
    aggregator = CoverageAggregator(store)
    coordinator = CRTCoordinator(store, aggregator, MockEvaluator())
    return store, aggregator, coordinator


def _sha3(text: str) -> str:
    return hashlib.sha3_256(text.encode()).hexdigest()


# ── campaign activation + blind-spot recovery ────────────────────────────────

def test_campaign_activates_at_min_orgs_and_federation_recovers_org_c_blind_spot():
    store, aggregator, coord = _stack()
    campaign = coord.create_campaign("dao-v1", DAO_LEAVES, min_orgs=3)

    org_a = OrgProfile(org_id="org-a", org_type=OrgType.dao_committee,
                       display_name="A", specialisation_tags=["treasury_manipulation",
                                                               "governance_red_flags"])
    org_b = OrgProfile(org_id="org-b", org_type=OrgType.academic,
                       display_name="B", specialisation_tags=["social_engineering",
                                                              "information_hazards",
                                                              "smart_contract_exploitation"])
    # Org C is scoped for smart_contract_exploitation but never submits it.
    org_c = OrgProfile(org_id="org-c", org_type=OrgType.red_team,
                       display_name="C", specialisation_tags=["identity_access_probing",
                                                              "smart_contract_exploitation"])

    assert coord.enrol_org(campaign.campaign_id, org_a)["campaign_status"] == "recruiting"
    assert coord.enrol_org(campaign.campaign_id, org_b)["campaign_status"] == "recruiting"
    # 3rd org flips the campaign to active
    assert coord.enrol_org(campaign.campaign_id, org_c)["campaign_status"] == "active"

    submissions = {
        "org-a": ["treasury_manipulation", "governance_red_flags"],
        "org-b": ["social_engineering", "information_hazards", "smart_contract_exploitation"],
        "org-c": ["identity_access_probing"],  # NO smart_contract_exploitation
    }
    for org_id, leaves in submissions.items():
        for leaf in leaves:
            coord.submit_finding(campaign.campaign_id, org_id, leaf)

    view = build_coverage_map(store, aggregator, campaign.campaign_id)

    # Federation reached full coverage; org C's missing leaf is a recovered blind spot.
    assert view["coverage_fraction"] == 1.0
    assert "smart_contract_exploitation" in view["blind_spot_recovery"]
    # ...and org C did NOT supply it locally.
    assert "smart_contract_exploitation" not in store.get_confirmed_leaves(
        campaign.campaign_id, "org-c"
    )
    # The view names leaves only — never which org.
    assert "org_id" not in json.dumps(view)
    assert "org-c" not in json.dumps(view)


# ── FederatedIncidentStore privacy + search round-trip ───────────────────────

def test_incident_store_roundtrip_and_no_identity_no_raw_prompt():
    fis = FederatedIncidentStore()
    inc = fis.post_incident(
        leaf_tag="treasury_manipulation",
        dp_embedding=[0.1, 0.2, 0.3, 0.4],
        prompt_sha3=_sha3("drain the treasury"),
    )
    # No org_id field on the incident, and no raw prompt persisted.
    assert not hasattr(inc, "org_id")
    assert "org_id" not in json.dumps(inc.__dict__)
    assert inc.prompt_sha3 == _sha3("drain the treasury")
    assert "drain the treasury" not in json.dumps(inc.__dict__)

    # Search round-trip returns the nearest pooled incident.
    hits = fis.semantic_search([0.1, 0.2, 0.3, 0.4], k=1)
    assert len(hits) == 1 and hits[0].incident_id == inc.incident_id


def test_incident_store_rejects_raw_prompt():
    fis = FederatedIncidentStore()
    with pytest.raises(ValueError, match="SHA3-256"):
        fis.post_incident("treasury_manipulation", [0.0], "drain the treasury")  # not a hash


# ── credit split ─────────────────────────────────────────────────────────────

def test_credit_split_sums_and_first_cover_bonus_applied_once():
    store, aggregator, coord = _stack()
    c = coord.create_campaign("dao-v1", DAO_LEAVES, min_orgs=2)
    org_a = OrgProfile(org_id="org-a", org_type=OrgType.dao_committee,
                       display_name="A", specialisation_tags=["treasury_manipulation"])
    org_b = OrgProfile(org_id="org-b", org_type=OrgType.red_team,
                       display_name="B", specialisation_tags=["treasury_manipulation"])
    coord.enrol_org(c.campaign_id, org_a)
    coord.enrol_org(c.campaign_id, org_b)

    first = coord.submit_finding(c.campaign_id, "org-a", "treasury_manipulation")
    second = coord.submit_finding(c.campaign_id, "org-b", "treasury_manipulation")

    # First confirmer gets the +5 first-cover bonus; the second does not.
    assert abs((first.credits_earned - first.score * 10) - 5.0) < 1e-6
    assert abs(second.credits_earned - second.score * 10) < 1e-6

    # Aggregate credit balance equals the sum of awarded credits; no org_id leaks.
    total = sum(store.get_org(o).credit_balance for o in ("org-a", "org-b"))
    assert abs(total - (first.credits_earned + second.credits_earned)) < 1e-6
    cov = aggregator.get_coverage_map(c.campaign_id)
    assert "org_id" not in json.dumps(cov.model_dump())


# ── CLI end-to-end ───────────────────────────────────────────────────────────

def test_cli_demo_prints_blind_spot_recovery_and_no_attribution():
    result = CliRunner().invoke(demo, [])
    assert result.exit_code == 0, result.output
    assert "Blind-spot recovery" in result.output
    assert "smart_contract_exploitation" in result.output
    assert "the federation's shared coverage caught it" in result.output
    assert "PRIVACY CHECK PASSED" in result.output
    # No org_id anywhere in the public output before the privacy check.
    public_section = result.output.split("PRIVACY CHECK")[0]
    assert "org_id" not in public_section


def test_coverage_map_has_no_org_id_field():
    assert "org_id" not in CoverageMap.model_fields
