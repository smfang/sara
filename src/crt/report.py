"""
CRT report builder.

report_hash = SHA3-256 of canonical JSON of PUBLIC fields only.
Attribution is never included — the hash is sized as the future ZK-circuit input.

Uses src.crypto.canonical.digest() (RFC 8785 JCS-aligned, single source of truth).
"""

from __future__ import annotations

from src.crypto.canonical import digest
from src.crt.models import CRTCampaign, CoverageMap, CRTReport


def build_report(
    campaign: CRTCampaign,
    coverage_map: CoverageMap,
    min_threshold: float = 0.8,
) -> CRTReport:
    met = coverage_map.coverage_fraction >= min_threshold

    # Build public fields dict — NO org_id, no attribution
    public = {
        "campaign_id": campaign.campaign_id,
        "target_id": campaign.target_id,
        "total_leaves": coverage_map.total_leaves,
        "covered_leaves": coverage_map.covered_leaves,
        "coverage_fraction": coverage_map.coverage_fraction,
        "participating_orgs_count": coverage_map.participating_orgs_count,
        "leaf_coverage": coverage_map.leaf_coverage,
        "leaf_scores": coverage_map.leaf_scores,
        "min_threshold": min_threshold,
        "min_threshold_met": met,
    }

    # digest() auto-injects schema_version; sorts keys; SHA3-256
    h = digest(public)

    return CRTReport(
        campaign_id=campaign.campaign_id,
        target_id=campaign.target_id,
        total_leaves=coverage_map.total_leaves,
        covered_leaves=coverage_map.covered_leaves,
        coverage_fraction=coverage_map.coverage_fraction,
        participating_orgs_count=coverage_map.participating_orgs_count,
        leaf_coverage=coverage_map.leaf_coverage,
        leaf_scores=coverage_map.leaf_scores,
        min_threshold=min_threshold,
        min_threshold_met=met,
        zk_proof_hex="",  # A.5-full: ZK proof of coverage without attribution
        report_hash=h,
    )
