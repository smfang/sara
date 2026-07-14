"""
Hard-sample (inconsistency) mining — GuardReasoner-Omni, arXiv 2602.03328.

For each gold row we sample G completions from the current policy and keep ONLY
the rows where the group is *inconsistent* w.r.t. the gold leaf — "neither all
correct nor all incorrect". Those boundary cases are where GRPO has signal; they
are also the weak-leaf feedback the RL spec (docs/review_rl.md) called ABSENT.

"Correct" is defined by the VERIFIABLE anchor (the Osprey gate match against the
gold leaf), never by the policy's own confidence — so mining can't be gamed.
"""

from __future__ import annotations

from src.agent_rl.tinker_spike.reward import GoldRow, OspreyGateMatcher, SaraCompletion


def is_gate_correct(gold: GoldRow, completion: SaraCompletion, matcher: OspreyGateMatcher) -> bool:
    """Correct = the predicted gate exactly matches the gold leaf (verifiable)."""
    return matcher.match(completion.predicted_gate, gold.expected_gate) == 1.0


def is_hard(gold: GoldRow, completions: list[SaraCompletion], matcher: OspreyGateMatcher) -> bool:
    """Boundary case: at least one correct AND at least one wrong across the group."""
    if not completions:
        return False
    correct = [is_gate_correct(gold, c, matcher) for c in completions]
    return any(correct) and not all(correct)


def mine_hard(
    rollouts: list[tuple[GoldRow, list[SaraCompletion]]],
    matcher: OspreyGateMatcher | None = None,
) -> list[GoldRow]:
    """Return the gold rows whose G completions are inconsistent (the GRPO batch)."""
    matcher = matcher or OspreyGateMatcher()
    return [gold for gold, comps in rollouts if is_hard(gold, comps, matcher)]


def weak_leaf_counts(
    rollouts: list[tuple[GoldRow, list[SaraCompletion]]],
    matcher: OspreyGateMatcher | None = None,
) -> dict[str, int]:
    """Count hard (inconsistent) rows per leaf — feeds weak-leaf retrieval so the
    next curriculum round pulls more examples for the leaves Sara is unstable on."""
    matcher = matcher or OspreyGateMatcher()
    counts: dict[str, int] = {}
    for gold, comps in rollouts:
        if is_hard(gold, comps, matcher):
            counts[gold.leaf] = counts.get(gold.leaf, 0) + 1
    return counts
