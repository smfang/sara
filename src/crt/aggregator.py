"""
CoverageAggregator — attribution-blind coverage tracking.

record_coverage() takes NO org_id by design. This enforces the privacy
invariant at the signature level: the aggregator physically cannot leak
org identity into the CoverageMap.

# A.5-full: diversity_score will be backed by MPC-aggregated type counts
#   so even the aggregator can't see which specific org contributed which type.
"""

from __future__ import annotations

from src.crt.models import CoverageMap
from src.crt.store import InMemoryCRTStore


class CoverageAggregator:

    def __init__(self, store: InMemoryCRTStore) -> None:
        self._store = store

    def record_coverage(self, campaign_id: str, tag: str, score: float) -> None:
        """Record that *tag* is now covered at *score*.

        Signature intentionally has NO org_id parameter — enforces attribution
        privacy at the type level. Private attribution is stored separately by
        InMemoryCRTStore._attribution (never returned in public objects).
        """
        self._store.record_coverage(campaign_id, tag, score)

    def is_covered(self, campaign_id: str, tag: str) -> bool:
        return self._store.is_covered(campaign_id, tag)

    def get_coverage_map(self, campaign_id: str) -> CoverageMap:
        campaign = self._store.get_campaign(campaign_id)
        if campaign is None:
            raise KeyError(f"Campaign {campaign_id!r} not found")

        leaf_coverage = {
            tag: self._store.is_covered(campaign_id, tag)
            for tag in campaign.target_taxonomy_tags
        }
        leaf_scores = {
            tag: self._store.get_leaf_score(campaign_id, tag)
            for tag in campaign.target_taxonomy_tags
        }
        covered = sum(1 for v in leaf_coverage.values() if v)
        total = len(leaf_coverage)

        return CoverageMap(
            campaign_id=campaign_id,
            leaf_coverage=leaf_coverage,
            leaf_scores=leaf_scores,
            total_leaves=total,
            covered_leaves=covered,
            coverage_fraction=round(covered / total, 6) if total else 0.0,
            participating_orgs_count=len(campaign.enrolled_org_ids),
        )

    def diversity_score(self, campaign_id: str) -> float:
        """Fraction of distinct contributing org_types out of 4 possible, clamped to 1.0.

        Spec denominator is 4; OrgType has 5 values, so clamping prevents >1.0
        when all 5 types contribute.
        """
        # A.5-full: back with MPC-aggregated type counts (no individual attribution)
        distinct = self._store.get_distinct_org_types(campaign_id)
        return round(min(1.0, len(distinct) / 4), 4)
