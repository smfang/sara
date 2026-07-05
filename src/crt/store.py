"""
InMemoryCRTStore — dict-backed store with the same method surface as a
future ClickHouse-backed store.

# A.5-full: swap for ClickHouse-backed store using arena.crt_sessions tables.
"""

from __future__ import annotations

from src.crt.models import CRTCampaign, OrgProfile, OrgSubmission


class InMemoryCRTStore:

    def __init__(self) -> None:
        self._campaigns: dict[str, CRTCampaign] = {}
        self._orgs: dict[str, OrgProfile] = {}
        self._submissions: dict[str, OrgSubmission] = {}

        # Public coverage — no org_id stored here
        self._covered: dict[str, dict[str, bool]] = {}   # campaign -> tag -> bool
        self._scores: dict[str, dict[str, float]] = {}   # campaign -> tag -> best_score

        # Private: attribution — NEVER returned in CoverageMap
        self._attribution: dict[str, dict[str, str]] = {}  # campaign -> tag -> first_org_id

        # Leaf assignments — tracks which org is primarily on each leaf (for non-overlapping dist.)
        self._assignments: dict[str, dict[str, str]] = {}  # campaign -> tag -> org_id

        # Contributing org types — aggregate only (no org_id); used for diversity_score
        self._contributing_types: dict[str, set[str]] = {}  # campaign -> set[org_type_str]

    # ── Campaigns ────────────────────────────────────────────────────────────

    def save_campaign(self, campaign: CRTCampaign) -> None:
        self._campaigns[campaign.campaign_id] = campaign

    def get_campaign(self, campaign_id: str) -> CRTCampaign | None:
        return self._campaigns.get(campaign_id)

    # ── Orgs ─────────────────────────────────────────────────────────────────

    def save_org(self, org: OrgProfile) -> None:
        self._orgs[org.org_id] = org

    def get_org(self, org_id: str) -> OrgProfile | None:
        return self._orgs.get(org_id)

    # ── Submissions ───────────────────────────────────────────────────────────

    def save_submission(self, sub: OrgSubmission) -> None:
        self._submissions[sub.submission_id] = sub

    def get_confirmed_leaves(self, campaign_id: str, org_id: str) -> set[str]:
        """Leaves an org has LOCAL data for (i.e. confirmed itself).

        PRIVATE read — used only to compute the attribution-blind blind-spot
        view in coverage_view; callers must emit leaf names, never org_id.
        """
        return {
            s.taxonomy_tag_claimed
            for s in self._submissions.values()
            if s.campaign_id == campaign_id
            and s.org_id == org_id
            and s.confirmed_coverage
        }

    # ── Coverage (public, no org_id) ─────────────────────────────────────────

    def record_coverage(self, campaign_id: str, tag: str, score: float) -> None:
        self._covered.setdefault(campaign_id, {})[tag] = True
        prev = self._scores.get(campaign_id, {}).get(tag, 0.0)
        self._scores.setdefault(campaign_id, {})[tag] = max(prev, score)

    def is_covered(self, campaign_id: str, tag: str) -> bool:
        return self._covered.get(campaign_id, {}).get(tag, False)

    def get_leaf_score(self, campaign_id: str, tag: str) -> float:
        return self._scores.get(campaign_id, {}).get(tag, 0.0)

    def record_private_attribution(self, campaign_id: str, tag: str, org_id: str) -> None:
        """Store first-confirmer org_id per tag — PRIVATE, never returned in public objects.

        # A.5-full: this table feeds dispute resolution and priority ordering
        #   in the on-chain ERC-8004 attestation flow.
        """
        self._attribution.setdefault(campaign_id, {}).setdefault(tag, org_id)

    # ── Leaf assignments ──────────────────────────────────────────────────────

    def record_leaf_assignment(self, campaign_id: str, org_id: str, tags: list[str]) -> None:
        for tag in tags:
            self._assignments.setdefault(campaign_id, {}).setdefault(tag, org_id)

    def get_assigned_leaves(self, campaign_id: str) -> set[str]:
        return set(self._assignments.get(campaign_id, {}).keys())

    # ── Contributing org types (aggregate, never org_id) ─────────────────────

    def record_contributing_org_type(self, campaign_id: str, org_type: str) -> None:
        self._contributing_types.setdefault(campaign_id, set()).add(org_type)

    def get_distinct_org_types(self, campaign_id: str) -> set[str]:
        return self._contributing_types.get(campaign_id, set())
