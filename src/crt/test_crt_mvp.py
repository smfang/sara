"""
CRT MVP test suite.

Run from project root:
    python -m pytest src/crt/test_crt_mvp.py -v
"""

from __future__ import annotations

import json

import pytest

from src.crt.aggregator import CoverageAggregator
from src.crt.coordinator import CRTCoordinator
from src.crt.mock_eval import MockEvaluator
from src.crt.models import CoverageMap, OrgProfile, OrgType
from src.crt.report import build_report
from src.crt.store import InMemoryCRTStore
from src.sarabox.taxonomy import DAO_TAXONOMY

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

DAO_LEAVES = [leaf["id"] for leaf in DAO_TAXONOMY[:6]]


def _make_stack():
    store = InMemoryCRTStore()
    aggregator = CoverageAggregator(store)
    evaluator = MockEvaluator()
    coordinator = CRTCoordinator(store, aggregator, evaluator)
    return store, aggregator, coordinator


def _org(org_id: str, org_type: OrgType, tags: list[str]) -> OrgProfile:
    return OrgProfile(
        org_id=org_id,
        org_type=org_type,
        display_name=f"Org {org_id}",
        specialisation_tags=tags,
    )


def _three_orgs():
    return [
        _org("org-a", OrgType.dao_committee, ["treasury_manipulation", "governance_red_flags"]),
        _org("org-b", OrgType.academic,      ["social_engineering", "information_hazards"]),
        _org("org-c", OrgType.red_team,      ["identity_access_probing", "smart_contract_exploitation"]),
    ]


# ---------------------------------------------------------------------------
# Campaign lifecycle
# ---------------------------------------------------------------------------

def test_campaign_starts_recruiting():
    _, _, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    assert c.status == "recruiting"
    assert c.started_at is None


def test_campaign_stays_recruiting_with_two_orgs():
    store, _, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES, min_orgs=3)
    orgs = _three_orgs()

    coord.enrol_org(c.campaign_id, orgs[0])
    assert store.get_campaign(c.campaign_id).status == "recruiting"

    coord.enrol_org(c.campaign_id, orgs[1])
    assert store.get_campaign(c.campaign_id).status == "recruiting"


def test_campaign_flips_to_active_on_third_org():
    store, _, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES, min_orgs=3)
    for org in _three_orgs():
        coord.enrol_org(c.campaign_id, org)
    campaign = store.get_campaign(c.campaign_id)
    assert campaign.status == "active"
    assert campaign.started_at is not None


def test_enrol_returns_assigned_leaves_and_status():
    _, _, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES, min_orgs=3)
    result = coord.enrol_org(c.campaign_id, _three_orgs()[0])
    assert "assigned_leaves" in result
    assert len(result["assigned_leaves"]) >= 1
    assert result["campaign_status"] in {"recruiting", "active"}


# ---------------------------------------------------------------------------
# Leaf assignment
# ---------------------------------------------------------------------------

def test_leaf_assignment_respects_specialisation():
    store, _, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    orgs = _three_orgs()

    r0 = coord.enrol_org(c.campaign_id, orgs[0])
    r1 = coord.enrol_org(c.campaign_id, orgs[1])
    r2 = coord.enrol_org(c.campaign_id, orgs[2])

    # Each org's assigned leaves should include their specialisation tags
    assert all(t in r0["assigned_leaves"] for t in orgs[0].specialisation_tags)
    assert all(t in r1["assigned_leaves"] for t in orgs[1].specialisation_tags)
    assert all(t in r2["assigned_leaves"] for t in orgs[2].specialisation_tags)


def test_no_leaf_assigned_twice_when_avoidable():
    store, _, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    orgs = _three_orgs()

    r0 = coord.enrol_org(c.campaign_id, orgs[0])
    r1 = coord.enrol_org(c.campaign_id, orgs[1])
    r2 = coord.enrol_org(c.campaign_id, orgs[2])

    # Since all 3 orgs have distinct non-overlapping specialisations covering all 6 leaves,
    # each leaf should be primarily assigned to exactly one org.
    all_assigned = r0["assigned_leaves"] + r1["assigned_leaves"] + r2["assigned_leaves"]
    assert len(all_assigned) == len(set(all_assigned)), "Same leaf was assigned to multiple orgs"


# ---------------------------------------------------------------------------
# Submissions and coverage
# ---------------------------------------------------------------------------

def test_submit_finding_requires_active_campaign():
    _, _, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    # Only 1 org enrolled → still recruiting
    coord.enrol_org(c.campaign_id, _three_orgs()[0])
    with pytest.raises(ValueError, match="not active"):
        coord.submit_finding(c.campaign_id, "org-a", "treasury_manipulation")


def test_submit_finding_rejects_unenrolled_org():
    _, _, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    for org in _three_orgs():
        coord.enrol_org(c.campaign_id, org)
    with pytest.raises(ValueError, match="not enrolled"):
        coord.submit_finding(c.campaign_id, "org-unknown", "treasury_manipulation")


def test_confirm_coverage_records_coverage_and_awards_credits():
    store, agg, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    for org in _three_orgs():
        coord.enrol_org(c.campaign_id, org)

    sub = coord.submit_finding(c.campaign_id, "org-a", "treasury_manipulation")

    assert sub.confirmed_coverage is True
    assert sub.score > 0
    assert sub.credits_earned > 0
    assert agg.is_covered(c.campaign_id, "treasury_manipulation")


def test_first_cover_bonus_applied_once():
    store, agg, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    for org in _three_orgs():
        coord.enrol_org(c.campaign_id, org)

    # First submission on a leaf gets the bonus
    sub_first = coord.submit_finding(c.campaign_id, "org-a", "treasury_manipulation")
    credits_first = sub_first.credits_earned

    # Second submission on the same leaf (org-b is enrolled; submit on same leaf)
    sub_second = coord.submit_finding(c.campaign_id, "org-b", "treasury_manipulation")
    credits_second = sub_second.credits_earned

    # First cover gives score×10 + 5; subsequent gives score×10 only
    assert credits_first > credits_second
    assert abs(credits_first - credits_second - 5.0) < 0.1


# ---------------------------------------------------------------------------
# Coverage fraction and diversity
# ---------------------------------------------------------------------------

def test_coverage_fraction_four_of_six():
    store, agg, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    for org in _three_orgs():
        coord.enrol_org(c.campaign_id, org)

    # Submit 4 of the 6 leaves
    four_leaves = DAO_LEAVES[:4]
    for i, leaf in enumerate(four_leaves):
        # Assign each to the right org based on the specialisation split
        org_id = "org-a" if i < 2 else "org-b"
        coord.submit_finding(c.campaign_id, org_id, leaf)

    cmap = agg.get_coverage_map(c.campaign_id)
    assert cmap.covered_leaves == 4
    assert cmap.total_leaves == 6
    assert abs(cmap.coverage_fraction - 4 / 6) < 1e-4


def test_coverage_fraction_full():
    store, agg, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    for org in _three_orgs():
        coord.enrol_org(c.campaign_id, org)

    assignments = {
        "org-a": ["treasury_manipulation", "governance_red_flags"],
        "org-b": ["social_engineering", "information_hazards"],
        "org-c": ["identity_access_probing", "smart_contract_exploitation"],
    }
    for org_id, leaves in assignments.items():
        for leaf in leaves:
            coord.submit_finding(c.campaign_id, org_id, leaf)

    cmap = agg.get_coverage_map(c.campaign_id)
    assert cmap.coverage_fraction == pytest.approx(1.0, abs=1e-4)


def test_diversity_score_three_distinct_types():
    store, agg, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    for org in _three_orgs():
        coord.enrol_org(c.campaign_id, org)

    # Each org confirms at least one leaf
    coord.submit_finding(c.campaign_id, "org-a", "treasury_manipulation")
    coord.submit_finding(c.campaign_id, "org-b", "social_engineering")
    coord.submit_finding(c.campaign_id, "org-c", "identity_access_probing")

    diversity = agg.diversity_score(c.campaign_id)
    assert diversity == pytest.approx(0.75, abs=1e-4)   # 3 / 4


# ---------------------------------------------------------------------------
# PRIVACY INVARIANT — the money-shot tests
# ---------------------------------------------------------------------------

def test_coverage_map_has_no_org_id_field():
    """CoverageMap.model_fields must not contain org_id — enforced at type level."""
    assert "org_id" not in CoverageMap.model_fields


def test_coverage_map_json_contains_no_org_id():
    """Serialised CoverageMap must not contain the string 'org_id'."""
    store, agg, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    for org in _three_orgs():
        coord.enrol_org(c.campaign_id, org)
    coord.submit_finding(c.campaign_id, "org-a", "treasury_manipulation")

    cmap = agg.get_coverage_map(c.campaign_id)
    assert "org_id" not in json.dumps(cmap.model_dump())


def test_finalise_returns_coverage_map_without_org_id():
    _, agg, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    for org in _three_orgs():
        coord.enrol_org(c.campaign_id, org)
    coord.submit_finding(c.campaign_id, "org-a", "treasury_manipulation")

    cmap = coord.finalise_campaign(c.campaign_id)
    assert isinstance(cmap, CoverageMap)
    assert "org_id" not in json.dumps(cmap.model_dump())


# ---------------------------------------------------------------------------
# Report hash
# ---------------------------------------------------------------------------

def test_report_hash_is_deterministic():
    _, agg, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    for org in _three_orgs():
        coord.enrol_org(c.campaign_id, org)
    coord.submit_finding(c.campaign_id, "org-a", "treasury_manipulation")
    cmap = agg.get_coverage_map(c.campaign_id)

    r1 = build_report(c, cmap)
    r2 = build_report(c, cmap)
    assert r1.report_hash == r2.report_hash
    assert len(r1.report_hash) == 64   # SHA3-256 hex


def test_report_hash_changes_when_coverage_changes():
    _, agg, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    for org in _three_orgs():
        coord.enrol_org(c.campaign_id, org)

    coord.submit_finding(c.campaign_id, "org-a", "treasury_manipulation")
    cmap1 = agg.get_coverage_map(c.campaign_id)
    r1 = build_report(c, cmap1)

    coord.submit_finding(c.campaign_id, "org-b", "social_engineering")
    cmap2 = agg.get_coverage_map(c.campaign_id)
    r2 = build_report(c, cmap2)

    assert r1.report_hash != r2.report_hash


def test_report_min_threshold_met_flag():
    _, agg, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    for org in _three_orgs():
        coord.enrol_org(c.campaign_id, org)

    # Cover only 4/6 → 66.7% — below 80% threshold
    for leaf in DAO_LEAVES[:4]:
        org_id = "org-a" if leaf in ["treasury_manipulation", "governance_red_flags"] else "org-b"
        coord.submit_finding(c.campaign_id, org_id, leaf)
    cmap = agg.get_coverage_map(c.campaign_id)
    r = build_report(c, cmap, min_threshold=0.8)
    assert r.min_threshold_met is False

    # Cover all 6 → 100% — above threshold
    for leaf in DAO_LEAVES[4:]:
        coord.submit_finding(c.campaign_id, "org-c", leaf)
    cmap2 = agg.get_coverage_map(c.campaign_id)
    r2 = build_report(c, cmap2, min_threshold=0.8)
    assert r2.min_threshold_met is True


# ---------------------------------------------------------------------------
# Taxonomy leaf IDs match fine-tuning seed
# ---------------------------------------------------------------------------

def test_dao_leaf_ids_match_crt_spec():
    """DAO_TAXONOMY leaf IDs must match the CRT spec to prevent fine-tuning divergence."""
    expected = [
        "identity_access_probing",
        "treasury_manipulation",
        "governance_red_flags",
        "social_engineering",
        "smart_contract_exploitation",
        "information_hazards",
    ]
    actual = [leaf["id"] for leaf in DAO_TAXONOMY[:6]]
    assert actual == expected


# ---------------------------------------------------------------------------
# CLI end-to-end (no network / DB)
# ---------------------------------------------------------------------------

def test_cli_demo_runs_end_to_end(capsys):
    from src.crt.cli import demo
    from click.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(demo, [])
    assert result.exit_code == 0, result.output
    assert "PRIVACY CHECK PASSED" in result.output
    assert "report_hash" in result.output
    # Check the public output before the privacy-check line contains no org_id —
    # including as a JSON key ("org_id"). No .replace() so a real leak would fail.
    public_section = result.output.split("PRIVACY CHECK")[0]
    assert '"org_id"' not in public_section, "PRIVACY BREACH: org_id appeared as JSON key in public output"
    assert "org_id" not in public_section, "PRIVACY BREACH: bare org_id string in public output"


# ---------------------------------------------------------------------------
# Edge cases and guard tests
# ---------------------------------------------------------------------------

def test_enrol_on_completed_campaign_raises():
    _, _, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    for org in _three_orgs():
        coord.enrol_org(c.campaign_id, org)
    coord.submit_finding(c.campaign_id, "org-a", "treasury_manipulation")
    coord.finalise_campaign(c.campaign_id)

    extra_org = _org("org-extra", OrgType.auditor, ["information_hazards"])
    with pytest.raises(ValueError, match="already completed"):
        coord.enrol_org(c.campaign_id, extra_org)


def test_submit_on_completed_campaign_raises():
    _, _, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES)
    for org in _three_orgs():
        coord.enrol_org(c.campaign_id, org)
    coord.finalise_campaign(c.campaign_id)

    with pytest.raises(ValueError, match="not active"):
        coord.submit_finding(c.campaign_id, "org-a", "treasury_manipulation")


def test_diversity_score_clamped_to_one_with_all_five_types():
    """5 OrgTypes / 4 = 1.25 — must be clamped to 1.0."""
    store, agg, coord = _make_stack()
    c = coord.create_campaign("target-1", DAO_LEAVES, min_orgs=2)

    all_five = [
        _org("o1", OrgType.dao_committee, ["treasury_manipulation"]),
        _org("o2", OrgType.academic,      ["governance_red_flags"]),
        _org("o3", OrgType.red_team,      ["social_engineering"]),
        _org("o4", OrgType.auditor,       ["identity_access_probing"]),
        _org("o5", OrgType.platform,      ["smart_contract_exploitation"]),
    ]
    for org in all_five[:2]:
        coord.enrol_org(c.campaign_id, org)  # activates on min_orgs=2
    for org in all_five[2:]:
        coord.enrol_org(c.campaign_id, org)

    for org in all_five:
        coord.submit_finding(c.campaign_id, org.org_id, org.specialisation_tags[0])

    score = agg.diversity_score(c.campaign_id)
    assert score <= 1.0, f"diversity_score must be clamped to 1.0, got {score}"
    assert score == pytest.approx(1.0)
