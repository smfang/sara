"""
coverage_view — build the public, attribution-blind coverage view for a campaign.

Adds the "blind-spot recovery" line the presentation turns on: leaves an enrolled
org was scoped for but had NO local data on, that the FEDERATION covered anyway.
The view NAMES leaves only — never which org lacked or supplied them.

Privacy: reads org scope + confirmed leaves privately to compute the blind-spot
set, but emits leaf names only. Output is asserted to contain no org_id.
"""

from __future__ import annotations

import json

from src.crt.aggregator import CoverageAggregator
from src.crt.store import InMemoryCRTStore


def build_coverage_map(
    store: InMemoryCRTStore,
    aggregator: CoverageAggregator,
    campaign_id: str,
) -> dict:
    """Return the public coverage view as a plain dict (no org identity).

    Keys: campaign_id, leaf_coverage, leaf_scores, covered_leaves, total_leaves,
    coverage_fraction, participating_orgs_count, blind_spot_recovery.
    """
    campaign = store.get_campaign(campaign_id)
    if campaign is None:
        raise KeyError(f"Campaign {campaign_id!r} not found")

    cov = aggregator.get_coverage_map(campaign_id)

    # Blind-spot recovery: a leaf L an enrolled org was scoped for (in its
    # specialisation) but never confirmed locally, yet the federation covered.
    recovered: set[str] = set()
    campaign_leaves = set(campaign.target_taxonomy_tags)
    for org_id in campaign.enrolled_org_ids:
        org = store.get_org(org_id)
        if org is None:
            continue
        scope = set(org.specialisation_tags) & campaign_leaves
        local = store.get_confirmed_leaves(campaign_id, org_id)
        for leaf in scope:
            if leaf not in local and cov.leaf_coverage.get(leaf):
                recovered.add(leaf)  # names the leaf, never the org

    view = {
        "campaign_id": campaign_id,
        "leaf_coverage": cov.leaf_coverage,
        "leaf_scores": cov.leaf_scores,
        "covered_leaves": cov.covered_leaves,
        "total_leaves": cov.total_leaves,
        "coverage_fraction": cov.coverage_fraction,
        "participating_orgs_count": cov.participating_orgs_count,
        "blind_spot_recovery": sorted(recovered),
    }

    # Privacy tripwire: the public view must never carry org identity.
    assert "org_id" not in json.dumps(view), "PRIVACY BREACH: org_id in coverage view"
    return view
