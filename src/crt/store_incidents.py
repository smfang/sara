"""
FederatedIncidentStore — the shared incident memory that makes the coverage map
*mean* something (the DAO analogue of a Federated RAG store).

Each org posts a differential-privacy-noised embedding of a CONFIRMED attack,
keyed by leaf tag. Any org can then semantically search the pooled incidents to
recover a class it has no local data for — the missing-class recovery result
from Fernández Saura et al., FGCS 178 (2026) 108319, retold for DAO red teaming.

Privacy: stores NO org_id, NO raw prompt text (SHA3-256 handle only), and no raw
vector semantics (mock floats). Attribution stays in the private store.

In-memory, ClickHouse/OpenSearch-shaped surface.
# A.5-full: real DP (epsilon ~ 1), real sentence embeddings, OpenSearch, TEE.
"""

from __future__ import annotations

import math
import re
import uuid
from dataclasses import dataclass, field
from typing import List

_SHA3_HEX = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class Incident:
    """A pooled, attribution-blind incident.

    NOTE: intentionally has NO org_id field and NO raw prompt field.
    """
    incident_id: str
    leaf_tag: str
    dp_embedding: List[float]   # MOCK DP-noised embedding — never a real vector
    prompt_sha3: str            # SHA3-256(prompt) handle — never the raw prompt


class FederatedIncidentStore:
    """In-memory pooled incident store with a semantic-search surface."""

    def __init__(self) -> None:
        self._incidents: List[Incident] = []

    def post_incident(
        self,
        leaf_tag: str,
        dp_embedding: List[float],
        prompt_sha3: str,
    ) -> Incident:
        """Pool a confirmed-attack incident.

        Rejects anything that is not a 64-char SHA3-256 hex handle, so a raw
        prompt can never be persisted here by mistake (privacy invariant).
        """
        if not isinstance(prompt_sha3, str) or not _SHA3_HEX.match(prompt_sha3):
            raise ValueError(
                "prompt_sha3 must be a 64-char SHA3-256 hex digest — "
                "raw prompt text must never be posted to the incident store"
            )
        incident = Incident(
            incident_id=uuid.uuid4().hex[:12],
            leaf_tag=leaf_tag,
            dp_embedding=list(dp_embedding),
            prompt_sha3=prompt_sha3,
        )
        self._incidents.append(incident)
        return incident

    def semantic_search(self, query_embedding: List[float], k: int = 5) -> List[Incident]:
        """Return the k nearest pooled incidents by (mock) embedding distance.

        # A.5-full: replace linear scan + euclidean with OpenSearch kNN over
        # real sentence embeddings inside a TEE.
        """
        scored = [
            (self._distance(query_embedding, inc.dp_embedding), inc)
            for inc in self._incidents
        ]
        scored.sort(key=lambda pair: pair[0])
        return [inc for _, inc in scored[: max(0, k)]]

    def incidents_for_leaf(self, leaf_tag: str) -> List[Incident]:
        return [inc for inc in self._incidents if inc.leaf_tag == leaf_tag]

    def __len__(self) -> int:
        return len(self._incidents)

    @staticmethod
    def _distance(a: List[float], b: List[float]) -> float:
        n = min(len(a), len(b))
        return math.sqrt(sum((a[i] - b[i]) ** 2 for i in range(n)))
