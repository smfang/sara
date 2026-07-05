"""
CRT CLI — demo command.

Usage (from project root):
    python -m src.crt.cli demo

Reproduces the showcase narrative:
  1. Create a 6-leaf DAO campaign (min_orgs=3)
  2. Enrol 3 orgs of distinct types
  3. Each submits findings on their assigned leaves
  4. Print coverage filling in
  5. Finalise; print CRTReport JSON + report_hash
  6. Assert no org identity in the public coverage map
"""

from __future__ import annotations

import json

import click

import hashlib

from src.crt.aggregator import CoverageAggregator
from src.crt.coordinator import CRTCoordinator
from src.crt.coverage_view import build_coverage_map
from src.crt.mock_eval import MockEvaluator
from src.crt.models import CoverageMap, OrgProfile, OrgType
from src.crt.report import build_report
from src.crt.store import InMemoryCRTStore
from src.crt.store_incidents import FederatedIncidentStore
from src.sarabox.taxonomy import DAO_TAXONOMY


def _mock_dp_embedding(text: str, dim: int = 8) -> list[float]:
    """Deterministic MOCK DP-noised embedding derived from a hash of *text*.

    # A.5-full: real sentence embedding + calibrated DP noise (epsilon ~ 1).
    """
    h = hashlib.sha256(text.encode()).digest()
    return [((h[i % len(h)] / 255.0) * 2 - 1) for i in range(dim)]


def _make_stack() -> tuple[InMemoryCRTStore, CoverageAggregator, CRTCoordinator]:
    store = InMemoryCRTStore()
    aggregator = CoverageAggregator(store)
    evaluator = MockEvaluator()
    coordinator = CRTCoordinator(store, aggregator, evaluator)
    return store, aggregator, coordinator


@click.group()
def cli() -> None:
    """Collaborative Red Teaming — MVP demo."""


@cli.command()
def demo() -> None:
    """End-to-end showcase: 3 orgs, 6 DAO leaves, coverage fills to 100%."""
    store, aggregator, coordinator = _make_stack()

    dao_leaves = [leaf["id"] for leaf in DAO_TAXONOMY[:6]]
    click.echo(f"\n{'='*60}")
    click.echo("  CRT MVP — Coverage-Shared, Attribution-Private")
    click.echo(f"{'='*60}")
    click.echo(f"Target: dao-v1  |  Leaves: {', '.join(dao_leaves)}\n")

    # Step 1: Create campaign
    campaign = coordinator.create_campaign(
        target_id="dao-v1",
        taxonomy_tags=dao_leaves,
        min_orgs=3,
    )
    click.echo(f"[Campaign] {campaign.campaign_id}  status={campaign.status}")

    # Step 2: Enrol 3 orgs with non-overlapping specialisations
    orgs = [
        OrgProfile(
            org_id="org-dao-01",
            org_type=OrgType.dao_committee,
            display_name="DAO Committee Alpha",
            specialisation_tags=["treasury_manipulation", "governance_red_flags"],
        ),
        OrgProfile(
            org_id="org-acad-02",
            org_type=OrgType.academic,
            display_name="University Red Lab",
            specialisation_tags=[
                "social_engineering",
                "information_hazards",
                "smart_contract_exploitation",
            ],
        ),
        # Org C — scoped for smart_contract_exploitation but has NO local data
        # for it; the federation will cover that leaf on its behalf.
        OrgProfile(
            org_id="org-rt-03",
            org_type=OrgType.red_team,
            display_name="Adversarial Security Group",
            specialisation_tags=["identity_access_probing", "smart_contract_exploitation"],
        ),
    ]

    for org in orgs:
        result = coordinator.enrol_org(campaign.campaign_id, org)
        click.echo(
            f"[Enrol]  {org.display_name:<30} "
            f"leaves={result['assigned_leaves']}  "
            f"campaign={result['campaign_status']}"
        )

    click.echo()

    # Step 3: Each org submits confirmed findings. Org C (org-rt-03) submits
    # ONLY identity_access_probing — it has no local data on
    # smart_contract_exploitation. org-acad-02 covers that leaf for the federation.
    incident_store = FederatedIncidentStore()
    assignments = {
        "org-dao-01": ["treasury_manipulation", "governance_red_flags"],
        "org-acad-02": ["social_engineering", "information_hazards", "smart_contract_exploitation"],
        "org-rt-03":   ["identity_access_probing"],
    }
    all_subs = []
    for org_id, leaves in assignments.items():
        org_name = next(o.display_name for o in orgs if o.org_id == org_id)
        for leaf in leaves:
            sub = coordinator.submit_finding(campaign.campaign_id, org_id, leaf)
            # Pool a DP-noised, attribution-blind incident (no org_id, sha3 only).
            prompt_sha3 = hashlib.sha3_256(f"{leaf}:{sub.submission_id}".encode()).hexdigest()
            incident_store.post_incident(
                leaf_tag=leaf,
                dp_embedding=_mock_dp_embedding(f"{leaf}:{sub.submission_id}"),
                prompt_sha3=prompt_sha3,
            )
            cmap = aggregator.get_coverage_map(campaign.campaign_id)
            all_subs.append(sub)
            bar = _coverage_bar(cmap.leaf_coverage, dao_leaves)
            click.echo(
                f"  [{org_name[:20]:<20}] +{leaf:<35} "
                f"{bar}  {cmap.covered_leaves}/{cmap.total_leaves} leaves"
            )

    click.echo()
    click.echo(f"Federated Incident Store: {len(incident_store)} pooled incidents "
               f"(no identity, SHA3 handles only)")

    # Step 4: Per-org summary
    click.echo("Per-org credits:")
    for org in orgs:
        loaded = store.get_org(org.org_id)
        subs = [s for s in all_subs if s.org_id == org.org_id]
        click.echo(f"  {loaded.display_name:<30}  credits={loaded.credit_balance:.2f}  subs={len(subs)}")

    diversity = aggregator.diversity_score(campaign.campaign_id)
    click.echo(f"\nDiversity score: {diversity:.2f}  (distinct org types / 4)")

    # Step 4b: Blind-spot recovery — the presentation payload.
    view = build_coverage_map(store, aggregator, campaign.campaign_id)
    click.echo(f"\nBlind-spot recovery: {view['blind_spot_recovery']}")
    for leaf in view["blind_spot_recovery"]:
        # The DAO retelling of the paper's missing-class recovery (75.85% -> 91.47%):
        # a scoped org had no local data on this leaf; the federation caught it.
        matches = incident_store.incidents_for_leaf(leaf)
        click.echo(
            f"  Org C (Adversarial Security Group) had NO local data on "
            f"'{leaf}' — the federation's shared coverage caught it "
            f"({len(matches)} pooled incident(s) now searchable by every org)."
        )

    # Step 5: Finalise
    click.echo()
    coverage_map = coordinator.finalise_campaign(campaign.campaign_id)
    report = build_report(campaign, coverage_map, min_threshold=0.8)

    click.echo(f"\ncoverage_fraction : {report.coverage_fraction:.4f}")
    click.echo(f"min_threshold_met : {report.min_threshold_met}")
    click.echo(f"report_hash       : {report.report_hash}")
    click.echo(f"\nCRTReport JSON:\n{json.dumps(report.model_dump(), indent=2, default=str)}")

    # Step 6: Privacy assertion
    click.echo(f"\n{'='*60}")
    public_json = json.dumps(coverage_map.model_dump())
    assert "org_id" not in public_json, "PRIVACY BREACH: org_id found in public coverage map!"
    assert "org_id" not in CoverageMap.model_fields, "PRIVACY BREACH: org_id is a CoverageMap field!"
    click.echo("PRIVACY CHECK PASSED — no org identity in the public coverage map.")
    click.echo(f"{'='*60}\n")


def _coverage_bar(leaf_coverage: dict[str, bool], leaves: list[str]) -> str:
    return "[" + "".join("█" if leaf_coverage.get(l) else "░" for l in leaves) + "]"


# Allow `python -m src.crt.cli demo`
if __name__ == "__main__":
    cli()
