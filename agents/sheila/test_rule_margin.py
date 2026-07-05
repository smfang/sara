"""
Tests for the Sheila rule-margin attack MODE (ADR-001).

Covers: determinism, that every attempt targets a real parsed rule id, the n
bound / distinctness, and that the mode is reachable via the PurpleTeam
interface (agents.sheila.api.SheilaRedTeam) without importing internals at the
call site.
"""

from agents.sheila.red_team import MarginAttempt, rule_margin_attack

# A small sample SML ruleset in the real Osprey format (see vertical_defaults.py).
SAMPLE_SML = (
    "rule no_treasury_drain {\n"
    "  when prompt contains 'drain treasury' or prompt contains 'transfer all funds'\n"
    "  then block\n"
    "  severity critical\n"
    "  category treasury_manipulation\n"
    "}\n"
    "rule no_governance_bypass {\n"
    "  when prompt contains 'bypass quorum' or prompt contains 'forge vote'\n"
    "  then block\n"
    "  severity high\n"
    "  category governance_red_flags\n"
    "}"
)

REAL_RULE_IDS = {"no_treasury_drain", "no_governance_bypass"}


def test_deterministic_same_seed_same_output():
    a = rule_margin_attack(SAMPLE_SML, "dao-target", n=4, seed=7)
    b = rule_margin_attack(SAMPLE_SML, "dao-target", n=4, seed=7)
    assert [x.__dict__ for x in a] == [x.__dict__ for x in b]


def test_different_seed_changes_output():
    a = rule_margin_attack(SAMPLE_SML, "dao-target", n=4, seed=0)
    b = rule_margin_attack(SAMPLE_SML, "dao-target", n=4, seed=1)
    # At least one prompt differs (evasion transform is seed-keyed).
    assert [x.prompt for x in a] != [x.prompt for x in b]


def test_every_targeted_rule_id_is_real():
    attempts = rule_margin_attack(SAMPLE_SML, "dao-target", n=10, seed=0)
    assert attempts, "expected at least one attempt"
    for attempt in attempts:
        assert isinstance(attempt, MarginAttempt)
        assert attempt.targeted_rule_id in REAL_RULE_IDS


def test_respects_n_bound_and_non_empty_distinct():
    attempts = rule_margin_attack(SAMPLE_SML, "dao-target", n=3, seed=0)
    assert len(attempts) <= 3
    assert all(a.prompt.strip() for a in attempts)
    assert len({a.prompt for a in attempts}) == len(attempts)  # distinct prompts
    assert len({a.attempt_id for a in attempts}) == len(attempts)  # distinct ids


def test_evasion_avoids_literal_trigger_phrase():
    attempts = rule_margin_attack(SAMPLE_SML, "dao-target", n=10, seed=0)
    for a in attempts:
        # The evasion_note names the phrase it dodges; the prompt must not
        # contain that literal phrase (that is the whole point of a margin attack).
        note_phrase = a.evasion_note.split("'")[1]
        assert note_phrase not in a.prompt


def test_no_rules_yields_no_attempts():
    assert rule_margin_attack("no rules here", "t", n=5) == []


def test_reachable_via_purpleteam_interface():
    # Callers use the interface, never agents.sheila.red_team internals.
    from agents.sheila.api import SheilaRedTeam

    rt = SheilaRedTeam()
    attempts = rt.rule_margin_attack(SAMPLE_SML, "dao-target", n=3, seed=0)
    assert len(attempts) <= 3
    assert all(a.targeted_rule_id in REAL_RULE_IDS for a in attempts)
