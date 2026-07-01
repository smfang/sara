## Task: Rename the Phoebe agent to Sheila across the codebase

**Run first.** This is a relabel, not a merge. Sheila stays a separate agent; her red-team/judge logic does not move into Sara.

### BEFORE WRITING ANY CODE:
1. Run: `find src/ agents/ -name "*.py" | head -50`
2. Check if `src/sarabox/` exists and list its contents
3. Check if `agents/sheila/` (formerly `agents/phoebe/`) exists and list its contents
4. Check if `src/crypto/` and `src/rl_training/` exist
5. Report what you find BEFORE proceeding. Do not duplicate existing modules.

### Scope (DO):
- Rename directory `agents/phoebe/` -> `agents/sheila/`
- Rename `PHOEBE_CONFIG` -> `SHEILA_CONFIG`; class/identifier `'Phoebe'` -> `'Sheila'`
- Update all imports, docstrings, mode prompts, and README references
- Update env vars: `PHOEBE_A2A_URL` -> `SHEILA_A2A_URL` (keep a deprecated alias)

### Scope (DO NOT):
- Do NOT move red-team or judge logic into Sara / `src/safety/`
- Do NOT merge the two agents; Sheila remains the inward-facing adversary+judge
- Do NOT change scoring weights or attestation formats

### Enforce the boundary:
- Sara code must import Sheila ONLY via the PurpleTeam interface (`PurpleTeam.judge()`, `PurpleTeam.run_session()`) — never internals.
- Add a CI check (`tests/test_boundary.py`) that fails if any module under `src/safety/` or `src/sarabox/` imports from `agents.sheila` internals.

### Verify:
```bash
python3 -m pytest tests/ -q 2>&1 | tail -5
grep -ri 'phoebe' src/ agents/ --include=*.py | grep -v 'deprecated alias' || echo 'clean'
```
