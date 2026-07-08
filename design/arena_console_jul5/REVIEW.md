# Review — Arena "Sara & Sheila Console" design handoff (Jul 5)

Read-only review of `design/arena_console_jul5/` against the current repo. Verdict:
**strong, well-documented mid-fidelity handoff** — tokens are lifted verbatim from
the real `:root`, labels are realistic, and each view lists its backend endpoints.
The issues below are about **structure, taxonomy/endpoint fit, and scope**, not
visual quality.

## What's good (keep as-is)
- Design tokens (colors/type/radii) copied from `src/ui/monitor.html`/`sheila.html` — visually consistent with the repo.
- Per-view backend endpoints are documented, and the README explicitly says **do not ship** `support.js` / `<x-dc>` markup (it's a design-tool export). Correct.
- Sheila Attack Runner maps cleanly onto the real `/api/submit` flow (which we just fixed) + existing commitment-hash/EVM-wallet UI.

## Blocking decisions (resolve before building)

1. **SPA console vs. restyle existing pages.** The design is one single-page console with client-side section/tab switching. The real app is **separate server-rendered pages per route** (`/tns`, `/monitor`, `/sheila`, `/redteam`, `/crt`). Either (a) build a new unified shell that hosts everything, or (b) apply the look to the existing separate pages. (a) is a real rearchitecture; (b) is faster and lower-risk. **Recommend (b) first**, page by page.

2. **Scope gap — pages the design drops.** The console covers only Sara (Overview/Classify/Rules/Violations) + Sheila (Attack/Create Bounty). It **omits**: Researcher, Admin, SaraBox, ZK Trail, DPO, **and the CRT blind-spot page + Sheila rule-margin panel we just built**. Decide: fold these into the console, keep them as separate pages, or drop them.

3. **Brand rename "Arena."** Top-level rebrands to "Arena" with SARA/SHEILA pills, replacing the current `⬡ Sara` + nav. Confirm the rename is intended (affects header, titles, docs).

## Data / endpoint mismatches (wiring)

4. **Two taxonomies conflated.** The design mixes a generic T&S taxonomy (`credential_extraction`, `spam_coordination`, `self_harm`, filters `identity·credential·injection·spam·self_harm`, "7 categories") with the real DAO taxonomy. The repo has **two distinct** ones: GA-Guard `PolicyCategory` (drives the safety classifier) and `DAO_TAXONOMY` = 6 leaves (`identity_access_probing`, `treasury_manipulation`, `governance_red_flags`, `social_engineering`, `smart_contract_exploitation`, `information_hazards`). Decide which drives the console; the Classify screenshot uses a real leaf (`identity_access_probing`) but the Rules filters use generic ones.

5. **Classify result shape.** Design shows Category / Confidence `0.91` / Severity `HIGH` / **Suggested action `ALERT`**. Real `/api/tns/classify` returns `{unsafe, severity: 0–5 int, policy_category, matched_block_rule, explanation}` — **no confidence 0–1 and no suggested-action field**. Needs an adapter or a backend field addition. Also: classify with no category loops **every** PolicyCategory (many Kimi calls, slow) — the UI should default to a chosen category or a single-pass endpoint.

6. **Monitor columns mostly empty.** SEVERITY / ATLAS TACTIC / PROOF ID: the README itself notes severity + ATLAS aren't on raw monitor events (render "—"), and PROOF ID (`erc8004_tx_hash`) is empty in dev. Set expectations or extend the event schema before promising these columns.

7. **Compiled-SML dialect wrong.** The detail panel shows `Rule PrivateAddressElicitation: when Session.intent == "solicit_pii" …`. Real Osprey SML (see `vertical_defaults.py`) is `rule no_x { when prompt contains '…' then block … }`. The sample SML should reflect the repo's actual dialect.

8. **Vertical packs don't exist as shown.** Design: Insurance 14 / Healthcare 19 / Financial 22. Repo `vertical_defaults.py`: **insurance + critical-infra, 6 rules each** — no Healthcare/Financial packs. Reconcile names + counts, or build the packs.

9. **Tool/endpoint naming drift.** README cites `osprey.listRuleFiles/readRuleFile/saveRule/validateRules`, `bounty.list/get/taxonomy`. Actual routes: `/osprey/rules/{org_id}` (GET), `/osprey/rules` (POST), `/osprey/rules/validate`, `/api/bounties`, `/api/taxonomy`. Wire to the real routes.

10. **Stat sources unverified.** AVG CONFIDENCE 0.86, SHEILA ATTACKS 24H 128, Catch rate 93%, TOP WEAK SPOT F1 0.54 — several have no existing aggregation endpoint. Identify real sources or add small stats endpoints; don't hardcode.

## Production / polish

11. **`.dc.html` + `support.js` are not usable directly** — reimplement in the existing plain-HTML/CSS/vanilla-JS pattern (README confirms). Treat the HTML as spec, not source.
12. **Drop the Google-Fonts dependency** — keep the system monospace stack already in the repo (JetBrains Mono as fallback only); avoids an external/CSP dependency.
13. **Desktop-only.** Inline styles + fixed pixel grid columns, no breakpoints. Fine for an internal console; note it.
14. **Re-export screenshot 05** — the Attack Runner render is a duplicate of Create Bounty (06); the SUBMIT ATTACK + RESULTS·SARA VERDICT view isn't captured.

## Recommended path
Start with **one page as a proof-of-concept**, restyling the existing page (option 1b) — **Policy Rules** or **Classify** — wired to real endpoints, resolving the taxonomy question (#4) on that page. Validate look + wiring, then roll the shell/tokens out to the rest and decide the fate of the omitted pages (#2), including the CRT/rule-margin work.
