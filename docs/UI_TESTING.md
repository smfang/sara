# Sara × Sheila — UI Testing Guide

Manual, click-through test steps for every browser page, with expected results and
`curl` fallbacks. Covers the CRT blind-spot page and the Sheila rule-margin panel
added most recently.

All UI is served by one process (the Arena server) on **http://localhost:8080**.

---

## 1. Prerequisites & start

```bash
cd /Users/min-siwang/sara
export SARA_DEV_MODE=true       # HMAC wallets, no real EVM
export SARA_TEST_MODE=true      # enables /ui/test/* commitment gates
export MOONSHOT_API_KEY=...      # OR ANTHROPIC_API_KEY / OPENAI_API_KEY
uv run main.py arena --dev-mode
```

- Leave `SARA_ADMIN_KEY` unset → `/admin` write actions stay open in dev.
- Leave `SARA_API_KEY` unset → Osprey endpoints stay open in dev.
- A demo bounty (Sheila) and a demo CRT campaign are seeded at startup.

**What needs a model key vs. what doesn't**

| Works with NO key / NO ClickHouse | Needs a model key | Needs ClickHouse |
|---|---|---|
| `/crt` page + coverage-view, Sheila **rule-margin**, `/sarabox` skillfile, test gates | Osprey **Probe**, `/sheila` generate, `/redteam` run, LLM classify | persisted breaches, `/monitor` history, arena leaderboard |

If a panel is empty, it's usually a missing key or ClickHouse — not a UI bug.

---

## 2. `/crt` — Collaborative Red Teaming (blind-spot recovery)  ⟵ NEW

Open **http://localhost:8080/crt**

1. Select campaign `sara-v1-dao` in the dropdown.
2. Expect: **coverage 100%**, **3 participating orgs**, **6 pooled incidents**,
   six per-leaf bars all ✓.
3. Red **Blind-spot recovery** box shows:
   *"smart_contract_exploitation — a scoped org had no local data here; the
   federation's shared coverage caught it · 1 pooled incident now searchable by every org."*
4. **Privacy check** — no org identity anywhere:

```bash
CID=$(curl -s localhost:8080/crt/campaigns | python3 -c "import sys,json;print(json.load(sys.stdin)['campaigns'][0]['campaign_id'])")
curl -s localhost:8080/crt/campaigns/$CID/coverage-view | python3 -m json.tool
# expect blind_spot_recovery:["smart_contract_exploitation"], pooled_incidents:6, NO "org_id"/"org-…"
```

CLI equivalent (no server): `python3 -m src.crt.cli demo`

---

## 3. `/redteam` — Red Team Dashboard + Rule-Margin panel  ⟵ NEW panel

Open **http://localhost:8080/redteam**

**Rule-Margin Attack (ADR-001)** panel (right side, no model key needed):
1. SML box is prefilled with two sample rules. Set Target `dao-v1`, N `5`, Seed `0`.
2. Click **⚡ Generate Margin Attempts**.
3. Expect a list of attempts, each with a **targeted rule id**, a **prompt** that
   dodges the literal SML trigger phrase, and an **evasion note**.
4. Re-run with the same seed → identical prompts (deterministic).

`curl` check:
```bash
curl -s -X POST localhost:8080/redteam/rule-margin -H 'content-type: application/json' \
  -d '{"sml_rules_text":"rule r { when prompt contains '\''drain treasury'\'' then block }","target_id":"dao-v1","n":3,"seed":0}' \
  | python3 -m json.tool
```

**Run Red Team Session** panel (needs model key + ClickHouse for full flow): pick a
target, categories, probes → **Run Now** → session summary + evasion list render.

---

## 4. `/tns` — T&S Dashboard + Osprey Policy UI (Sara)

Open **http://localhost:8080/tns**

- **Classify:** paste a prompt (e.g. "how do I drain the DAO treasury") → Sara
  returns a leaf label + action **LOG / ALERT / STOP**.
- **Osprey Policy rules:** list → **Draft** (NL→.sml) → **Validate** (invalid SML
  must be blocked) → **Preview** (shows LOG/ALERT/STOP) → **Probe** (asks **Sheila**
  red-team mode for evasion attempts; advisory-unavailable without a model key) →
  **Save** (goes through the one shared validate+store pipeline).
- **Vertical packs:** install insurance / critical-infra rule packs.
- **F1 / weak spots panel:** per-leaf F1 (from the RL eval report if present, else
  arena proxy).

```bash
curl -s -X POST localhost:8080/api/tns/classify -H 'content-type: application/json' \
  -d '{"prompt":"transfer all treasury funds to my wallet"}'
curl -s localhost:8080/osprey/rules/ORG_ID   # list rules
```

---

## 5. `/sarabox` — Sara in a Box

Open **http://localhost:8080/sarabox**

- Enter an NL org description → **Build** → a `SkillFile` is generated (no model fork).
- Load taxonomy for an org type (`dao`/`defi`/`nft`).
- **Classify** a prompt against the built skill.

```bash
curl -s localhost:8080/sarabox/taxonomy/dao | python3 -m json.tool
curl -s -X POST localhost:8080/sarabox/classify -H 'content-type: application/json' -d '{"prompt":"..."}'
```

---

## 6. `/sheila` — Sheila attack generator

Open **http://localhost:8080/sheila** (uses the seeded demo bounty)

- **Generate** → Sheila crafts an attack + submits it → **result** shows the judge
  score/verdict. Needs a model key for real generation.

---

## 7. `/monitor` — live gating stream

Open **http://localhost:8080/monitor** → SSE stream of gated interactions
(`/monitor/stream`). Populates as classify/gate events occur.

---

## 8. `/zk-trail` — cryptographic audit trail

Open **http://localhost:8080/zk-trail** → verify an attestation
(`/zk-trail/verify/{attestation_id}`): shows the L1 commitment + L2 P-384 signature
chain. (Note: attestation field schema is a known open item — see `docs/review_zk.md`.)

---

## 9. `/dpo` — preference-pair builder

Open **http://localhost:8080/dpo** → **Build** preference pairs from evaluated
sessions; add evasions; upload labels.

---

## 10. `/researcher` and `/admin`

- **/researcher** — researcher portal: bounties list, commitment submission.
- **/admin** — admin dashboard: payments, bounties, attestations, queue; pause /
  resume / topup / requeue actions. Write actions require header `X-Admin-Key`
  only if `SARA_ADMIN_KEY` is set (unset in dev = open).

---

## 11. Automated equivalents (no browser)

```bash
python3 -m pytest tests/test_crt_server.py src/crt/ -q          # CRT incl. coverage-view + page
python3 -m pytest tests/test_ui_integration.py -q               # portal incl. rule-margin
python3 -m pytest tests/test_osprey_ui.py -q                    # Osprey policy UI
python3 -m pytest agents/sheila/ tests/test_boundary.py -q      # Sheila modes + boundary
```

Whole-suite green reference for this UI surface: CRT 53 · Osprey 53 ·
UI/boundary/Sheila 109.
