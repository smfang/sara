"""
CRT data models.

Privacy invariant: CoverageMap has NO org_id field — enforced at the type level.
Attribution lives only in the private store tables, never in any public artifact.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class OrgType(str, Enum):
    dao_committee = "dao_committee"
    academic = "academic"
    red_team = "red_team"
    auditor = "auditor"
    platform = "platform"


class OrgProfile(BaseModel):
    model_config = ConfigDict(frozen=False)

    org_id: str
    org_type: OrgType
    display_name: str
    specialisation_tags: list[str] = Field(default_factory=list)
    credit_balance: float = 0.0


class CRTCampaign(BaseModel):
    model_config = ConfigDict(frozen=False)

    campaign_id: str
    target_id: str
    target_taxonomy_tags: list[str]
    enrolled_org_ids: list[str] = Field(default_factory=list)
    min_orgs: int = 3
    status: Literal["recruiting", "active", "completed"] = "recruiting"
    started_at: datetime | None = None
    completed_at: datetime | None = None


class OrgSubmission(BaseModel):
    model_config = ConfigDict(frozen=False)

    submission_id: str
    campaign_id: str
    org_id: str
    taxonomy_tag_claimed: str
    confirmed_coverage: bool = False
    score: float = 0.0
    credits_earned: float = 0.0


class CoverageMap(BaseModel):
    """
    Public coverage artifact.

    PRIVACY INVARIANT: this class has NO org_id field — enforced at the
    type level so the compiler prevents accidental attribution leakage.
    Attribution ({tag: org_id}) lives only in InMemoryCRTStore._attribution
    and is never serialised into this object or any JSON derived from it.
    """

    campaign_id: str
    leaf_coverage: dict[str, bool] = Field(default_factory=dict)
    leaf_scores: dict[str, float] = Field(default_factory=dict)
    total_leaves: int = 0
    covered_leaves: int = 0
    coverage_fraction: float = 0.0
    participating_orgs_count: int = 0


class CRTReport(BaseModel):
    model_config = ConfigDict(frozen=False)

    campaign_id: str
    target_id: str
    total_leaves: int
    covered_leaves: int
    coverage_fraction: float
    participating_orgs_count: int
    leaf_coverage: dict[str, bool]
    leaf_scores: dict[str, float]
    min_threshold: float = 0.8
    min_threshold_met: bool = False
    zk_proof_hex: str = ""  # A.5-full: ZK proof of coverage without attribution
    report_hash: str = ""
