"""
OS-04: Pre-compiled PolicyRule packs for Insurance and Critical-Infrastructure verticals.

Each pack ships six default rules covering the most common attack vectors
for that vertical. All rules are editable via the Policy UI (OS-03).
"""

from __future__ import annotations

from datetime import datetime, timezone

from src.osprey_ui.models import PolicyRule

# ---------------------------------------------------------------------------
# Insurance vertical (6 rules)
# ---------------------------------------------------------------------------

INSURANCE_DEFAULT_RULES: list[PolicyRule] = [
    PolicyRule(
        org_id="",
        display_name="No insurance fraud facilitation",
        natural_language=(
            "Block requests that help stage accidents, fake injuries, "
            "or exaggerate losses to file fraudulent insurance claims"
        ),
        osprey_sml=(
            "rule no_insurance_fraud {\n"
            "  when prompt contains 'stage accident' or prompt contains 'fake injury' "
            "or prompt contains 'exaggerate loss' or prompt contains 'false claim' "
            "or prompt contains 'inflate claim' or prompt contains 'phantom vehicle'\n"
            "  then block\n"
            "  severity critical\n"
            "  category illicit_activities\n"
            "}"
        ),
        category="illicit_activities",
        severity="critical",
        action="STOP",
        confidence_threshold=0.65,
        created_by="system",
        created_at=datetime.now(timezone.utc),
    ),
    PolicyRule(
        org_id="",
        display_name="No policyholder PII extraction",
        natural_language=(
            "Prevent extraction of policyholder personally identifiable information: "
            "SSN, date of birth, policy numbers, or medical history"
        ),
        osprey_sml=(
            "rule no_policyholder_pii {\n"
            "  when (prompt contains 'policyholder' or prompt contains 'insured') "
            "and (prompt contains 'ssn' or prompt contains 'social security' "
            "or prompt contains 'date of birth' or prompt contains 'policy number' "
            "or prompt contains 'medical history' or prompt contains 'diagnosis')\n"
            "  then block\n"
            "  severity critical\n"
            "  category pii_ip\n"
            "}"
        ),
        category="pii_ip",
        severity="critical",
        action="STOP",
        confidence_threshold=0.70,
        created_by="system",
        created_at=datetime.now(timezone.utc),
    ),
    PolicyRule(
        org_id="",
        display_name="No coverage exclusion bypass",
        natural_language=(
            "Flag attempts to circumvent coverage exclusions, hide pre-existing "
            "conditions, or misrepresent risk at policy application time"
        ),
        osprey_sml=(
            "rule no_coverage_bypass {\n"
            "  when prompt contains 'exclude' and (prompt contains 'bypass' "
            "or prompt contains 'hide' or prompt contains 'omit' "
            "or prompt contains 'pre-existing' or prompt contains 'misrepresent')\n"
            "  then alert\n"
            "  severity high\n"
            "  category illicit_activities\n"
            "}"
        ),
        category="illicit_activities",
        severity="high",
        action="ALERT",
        confidence_threshold=0.70,
        created_by="system",
        created_at=datetime.now(timezone.utc),
    ),
    PolicyRule(
        org_id="",
        display_name="No premium manipulation",
        natural_language=(
            "Block attempts to manipulate premium calculations, hide risk factors, "
            "or exploit rating algorithm weaknesses"
        ),
        osprey_sml=(
            "rule no_premium_manipulation {\n"
            "  when prompt contains 'premium' and (prompt contains 'lower' "
            "or prompt contains 'reduce' or prompt contains 'cheat' "
            "or prompt contains 'exploit' or prompt contains 'algorithm') "
            "and (prompt contains 'without' or prompt contains 'fraudulent' "
            "or prompt contains 'fake' or prompt contains 'bypass')\n"
            "  then alert\n"
            "  severity high\n"
            "  category illicit_activities\n"
            "}"
        ),
        category="illicit_activities",
        severity="high",
        action="ALERT",
        confidence_threshold=0.72,
        created_by="system",
        created_at=datetime.now(timezone.utc),
    ),
    PolicyRule(
        org_id="",
        display_name="No medical billing fraud",
        natural_language=(
            "Block upcoding requests, phantom billing schemes, or manipulation "
            "of CPT/ICD codes to obtain unauthorized reimbursement"
        ),
        osprey_sml=(
            "rule no_medical_billing_fraud {\n"
            "  when (prompt contains 'cpt code' or prompt contains 'icd code' "
            "or prompt contains 'medical billing' or prompt contains 'upcode' "
            "or prompt contains 'phantom billing') "
            "and (prompt contains 'fraud' or prompt contains 'fake' "
            "or prompt contains 'inflate' or prompt contains 'unauthorized')\n"
            "  then block\n"
            "  severity critical\n"
            "  category illicit_activities\n"
            "}"
        ),
        category="illicit_activities",
        severity="critical",
        action="STOP",
        confidence_threshold=0.68,
        created_by="system",
        created_at=datetime.now(timezone.utc),
    ),
    PolicyRule(
        org_id="",
        display_name="No claims adjuster social engineering",
        natural_language=(
            "Detect attempts to impersonate adjusters, fabricate witness statements, "
            "or manipulate the claims investigation process"
        ),
        osprey_sml=(
            "rule no_claims_social_engineering {\n"
            "  when (prompt contains 'adjuster' or prompt contains 'claims investigator' "
            "or prompt contains 'witness statement') "
            "and (prompt contains 'impersonat' or prompt contains 'fabricat' "
            "or prompt contains 'manipulate' or prompt contains 'pressure')\n"
            "  then alert\n"
            "  severity high\n"
            "  category social_engineering\n"
            "}"
        ),
        category="social_engineering",
        severity="high",
        action="ALERT",
        confidence_threshold=0.70,
        created_by="system",
        created_at=datetime.now(timezone.utc),
    ),
]

# ---------------------------------------------------------------------------
# Critical-infrastructure vertical (6 rules)
# ---------------------------------------------------------------------------

CRITICAL_INFRA_DEFAULT_RULES: list[PolicyRule] = [
    PolicyRule(
        org_id="",
        display_name="No SCADA/ICS attack guidance",
        natural_language=(
            "Block requests for attack methods against SCADA systems, "
            "industrial control systems, PLCs, or operational technology networks"
        ),
        osprey_sml=(
            "rule no_scada_attacks {\n"
            "  when (prompt contains 'scada' or prompt contains 'ics' "
            "or prompt contains 'plc' or prompt contains 'industrial control' "
            "or prompt contains 'operational technology' or prompt contains 'ot network') "
            "and (prompt contains 'attack' or prompt contains 'exploit' "
            "or prompt contains 'hack' or prompt contains 'compromise' "
            "or prompt contains 'disrupt')\n"
            "  then block\n"
            "  severity critical\n"
            "  category illicit_activities\n"
            "}"
        ),
        category="illicit_activities",
        severity="critical",
        action="STOP",
        confidence_threshold=0.60,
        created_by="system",
        created_at=datetime.now(timezone.utc),
    ),
    PolicyRule(
        org_id="",
        display_name="No power grid targeting",
        natural_language=(
            "Block requests for methods to attack electrical grid infrastructure: "
            "substations, transmission lines, generation facilities, or grid control systems"
        ),
        osprey_sml=(
            "rule no_power_grid_attacks {\n"
            "  when (prompt contains 'power grid' or prompt contains 'electrical grid' "
            "or prompt contains 'substation' or prompt contains 'transmission line' "
            "or prompt contains 'generation facility') "
            "and (prompt contains 'attack' or prompt contains 'disable' "
            "or prompt contains 'destroy' or prompt contains 'sabotage' "
            "or prompt contains 'blackout')\n"
            "  then block\n"
            "  severity critical\n"
            "  category violence_self_harm\n"
            "}"
        ),
        category="violence_self_harm",
        severity="critical",
        action="STOP",
        confidence_threshold=0.60,
        created_by="system",
        created_at=datetime.now(timezone.utc),
    ),
    PolicyRule(
        org_id="",
        display_name="No water treatment system attacks",
        natural_language=(
            "Block requests targeting water treatment facilities, "
            "distribution systems, or water quality monitoring infrastructure"
        ),
        osprey_sml=(
            "rule no_water_treatment_attacks {\n"
            "  when (prompt contains 'water treatment' or prompt contains 'water supply' "
            "or prompt contains 'reservoir' or prompt contains 'water distribution' "
            "or prompt contains 'drinking water') "
            "and (prompt contains 'contaminate' or prompt contains 'poison' "
            "or prompt contains 'disrupt' or prompt contains 'attack' "
            "or prompt contains 'chemical')\n"
            "  then block\n"
            "  severity critical\n"
            "  category illicit_activities\n"
            "}"
        ),
        category="illicit_activities",
        severity="critical",
        action="STOP",
        confidence_threshold=0.60,
        created_by="system",
        created_at=datetime.now(timezone.utc),
    ),
    PolicyRule(
        org_id="",
        display_name="No financial clearing system attacks",
        natural_language=(
            "Block requests targeting payment clearing systems, SWIFT infrastructure, "
            "central bank systems, or financial market integrity"
        ),
        osprey_sml=(
            "rule no_financial_clearing_attacks {\n"
            "  when (prompt contains 'swift' or prompt contains 'clearing system' "
            "or prompt contains 'central bank' or prompt contains 'payment infrastructure' "
            "or prompt contains 'fed wire' or prompt contains 'chips network') "
            "and (prompt contains 'attack' or prompt contains 'compromise' "
            "or prompt contains 'manipulate' or prompt contains 'disrupt' "
            "or prompt contains 'exploit')\n"
            "  then block\n"
            "  severity critical\n"
            "  category illicit_activities\n"
            "}"
        ),
        category="illicit_activities",
        severity="critical",
        action="STOP",
        confidence_threshold=0.65,
        created_by="system",
        created_at=datetime.now(timezone.utc),
    ),
    PolicyRule(
        org_id="",
        display_name="No telecom infrastructure attacks",
        natural_language=(
            "Flag requests for methods to attack telecommunications infrastructure: "
            "cell towers, fiber backbone, BGP routing, or 911 emergency dispatch systems"
        ),
        osprey_sml=(
            "rule no_telecom_attacks {\n"
            "  when (prompt contains 'cell tower' or prompt contains 'fiber backbone' "
            "or prompt contains 'bgp' or prompt contains 'routing table' "
            "or prompt contains '911 system' or prompt contains 'emergency dispatch') "
            "and (prompt contains 'attack' or prompt contains 'jam' "
            "or prompt contains 'hijack' or prompt contains 'disrupt' "
            "or prompt contains 'poison')\n"
            "  then alert\n"
            "  severity high\n"
            "  category illicit_activities\n"
            "}"
        ),
        category="illicit_activities",
        severity="high",
        action="ALERT",
        confidence_threshold=0.65,
        created_by="system",
        created_at=datetime.now(timezone.utc),
    ),
    PolicyRule(
        org_id="",
        display_name="No critical infrastructure insider threat enablement",
        natural_language=(
            "Detect requests to help insiders steal credentials, bypass access controls, "
            "or exfiltrate operational data from critical infrastructure environments"
        ),
        osprey_sml=(
            "rule no_ci_insider_threat {\n"
            "  when (prompt contains 'power plant' or prompt contains 'nuclear facility' "
            "or prompt contains 'pipeline' or prompt contains 'dam' "
            "or prompt contains 'airport' or prompt contains 'rail network') "
            "and (prompt contains 'insider' or prompt contains 'credentials' "
            "or prompt contains 'access control' or prompt contains 'bypass badge' "
            "or prompt contains 'exfiltrate')\n"
            "  then block\n"
            "  severity critical\n"
            "  category pii_ip\n"
            "}"
        ),
        category="pii_ip",
        severity="critical",
        action="STOP",
        confidence_threshold=0.65,
        created_by="system",
        created_at=datetime.now(timezone.utc),
    ),
]

# Registry: pack_name → list of rules
VERTICAL_PACKS: dict[str, list[PolicyRule]] = {
    "insurance": INSURANCE_DEFAULT_RULES,
    "critical_infrastructure": CRITICAL_INFRA_DEFAULT_RULES,
}
