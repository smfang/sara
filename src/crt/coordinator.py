"""
CRTCoordinator — campaign lifecycle, leaf assignment, submission confirmation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from src.crt.aggregator import CoverageAggregator
from src.crt.mock_eval import MockEvaluator
from src.crt.models import CRTCampaign, CoverageMap, OrgProfile, OrgSubmission
from src.crt.store import InMemoryCRTStore


class CRTCoordinator:

    def __init__(
        self,
        store: InMemoryCRTStore,
        aggregator: CoverageAggregator,
        evaluator: MockEvaluator,
    ) -> None:
        self._store = store
        self._aggregator = aggregator
        self._evaluator = evaluator

    # ── Campaign lifecycle ────────────────────────────────────────────────────

    def create_campaign(
        self,
        target_id: str,
        taxonomy_tags: list[str],
        min_orgs: int = 3,
    ) -> CRTCampaign:
        campaign = CRTCampaign(
            campaign_id=uuid.uuid4().hex[:12],
            target_id=target_id,
            target_taxonomy_tags=list(taxonomy_tags),
            min_orgs=min_orgs,
        )
        self._store.save_campaign(campaign)
        return campaign

    def enrol_org(self, campaign_id: str, org: OrgProfile) -> dict:
        campaign = self._store.get_campaign(campaign_id)
        if campaign is None:
            raise KeyError(f"Campaign {campaign_id!r} not found")
        if campaign.status == "completed":
            raise ValueError(f"Campaign {campaign_id!r} is already completed")

        self._store.save_org(org)

        assigned = self._assign_leaves(campaign, org)

        campaign.enrolled_org_ids.append(org.org_id)
        if (
            campaign.status == "recruiting"
            and len(campaign.enrolled_org_ids) >= campaign.min_orgs
        ):
            campaign.status = "active"
            campaign.started_at = datetime.now(timezone.utc)

        self._store.save_campaign(campaign)
        return {
            "org_id": org.org_id,
            "assigned_leaves": assigned,
            "campaign_status": campaign.status,
        }

    def _assign_leaves(self, campaign: CRTCampaign, org: OrgProfile) -> list[str]:
        """
        Assign leaves by specialisation; prefer leaves not yet assigned to any org
        (non-overlapping first). Falls back to any unassigned campaign leaf.
        """
        already: set[str] = self._store.get_assigned_leaves(campaign.campaign_id)
        taxonomy: set[str] = set(campaign.target_taxonomy_tags)

        # 1st priority: org's specialisations that are in taxonomy and unassigned
        unassigned_spec = [
            t for t in org.specialisation_tags
            if t in taxonomy and t not in already
        ]
        if unassigned_spec:
            result = unassigned_spec
        else:
            # 2nd priority: org's specialisations in taxonomy (even if taken)
            spec_in_taxonomy = [t for t in org.specialisation_tags if t in taxonomy]
            if spec_in_taxonomy:
                result = spec_in_taxonomy
            else:
                # Fallback: any unassigned campaign leaf
                result = [t for t in campaign.target_taxonomy_tags if t not in already][:2]

        self._store.record_leaf_assignment(campaign.campaign_id, org.org_id, result)
        return result

    # ── Submissions ───────────────────────────────────────────────────────────

    def submit_finding(
        self,
        campaign_id: str,
        org_id: str,
        taxonomy_tag: str,
    ) -> OrgSubmission:
        campaign = self._store.get_campaign(campaign_id)
        if campaign is None:
            raise KeyError(f"Campaign {campaign_id!r} not found")
        if campaign.status != "active":
            raise ValueError(
                f"Campaign {campaign_id!r} is not active (status={campaign.status!r})"
            )
        if org_id not in campaign.enrolled_org_ids:
            raise ValueError(f"Org {org_id!r} is not enrolled in campaign {campaign_id!r}")

        sub = OrgSubmission(
            submission_id=uuid.uuid4().hex[:12],
            campaign_id=campaign_id,
            org_id=org_id,
            taxonomy_tag_claimed=taxonomy_tag,
        )
        self.confirm_coverage(sub)
        self._store.save_submission(sub)
        return sub

    def confirm_coverage(self, submission: OrgSubmission) -> bool:
        result = self._evaluator.evaluate(
            submission.taxonomy_tag_claimed,
            submission.taxonomy_tag_claimed,
            submission.org_id,
        )
        if result["attack_success"] and result["coverage_category"] == submission.taxonomy_tag_claimed:
            submission.confirmed_coverage = True
            submission.score = result["total_score"]

            first_cover = not self._aggregator.is_covered(
                submission.campaign_id, submission.taxonomy_tag_claimed
            )
            # Record coverage WITHOUT org attribution (privacy invariant)
            self._aggregator.record_coverage(
                submission.campaign_id,
                submission.taxonomy_tag_claimed,
                result["total_score"],
            )
            # Store PRIVATE first-confirmer attribution (org_id + tag) — never in public artifacts
            self._store.record_private_attribution(
                submission.campaign_id, submission.taxonomy_tag_claimed, submission.org_id
            )
            # Record contributing org_type (aggregate only — no org_id exposed)
            org = self._store.get_org(submission.org_id)
            if org:
                self._store.record_contributing_org_type(
                    submission.campaign_id, org.org_type.value
                )

            credits = self._award_credits(submission.org_id, result["total_score"], first_cover)
            submission.credits_earned = credits
            return True
        return False

    def _award_credits(self, org_id: str, score: float, first_cover: bool) -> float:
        """score×10 + 5 bonus for being first to cover a leaf."""
        amount = score * 10 + (5.0 if first_cover else 0.0)
        org = self._store.get_org(org_id)
        if org:
            org.credit_balance += amount
            self._store.save_org(org)
        return round(amount, 4)

    # ── Finalise ──────────────────────────────────────────────────────────────

    def finalise_campaign(self, campaign_id: str) -> CoverageMap:
        campaign = self._store.get_campaign(campaign_id)
        if campaign is None:
            raise KeyError(f"Campaign {campaign_id!r} not found")

        campaign.status = "completed"
        campaign.completed_at = datetime.now(timezone.utc)
        self._store.save_campaign(campaign)

        # A.5-full: real on-chain write here (ERC-8004 attestation publisher)
        print(f"[ERC-8004 STUB] mock attestation logged for campaign {campaign_id}")

        return self._aggregator.get_coverage_map(campaign_id)
