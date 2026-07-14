"""
agent_eval — Sara/Sheila evaluate an EXTERNAL agent (e.g. a Claude legal-OS agent).

Neither Sara nor Sheila: this orchestrator drives a TargetAgent, gates its tool
calls with Sara (LegalActionGate ≈ an Osprey rule pack over actions), and judges
the trajectory. Imports Sheila only via the PurpleTeam interface (agents.sheila.api),
never internals — the boundary holds.
"""
