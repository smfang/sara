# Handoff: Arena — Sara & Sheila Trust & Safety Console

## Overview
A single-console UI for two trust-and-safety agents built on the Osprey / Arena stack:
- **Sara** — the *classifying agent*: classifies content, authors & validates Osprey policy rules, and surfaces live violations.
- **Sheila** — the *red-team agent*: runs adversarial attacks against target models via a USDC-funded **bounty arena**.

"Arena" is the platform/console brand (matches the real `src/arena/` module). Sara and Sheila are the two agents within it.

The console has two top-level sections (**Sara** / **Sheila**). Sara has four sub-views: **Overview, Classify, Policy Rules, Monitor Violations**. Sheila is a single view with an **Attack Runner** and a **Create Bounty** flow.

## About the Design Files
The files in this bundle are **design references created in HTML** — a prototype showing intended look, structure, and behavior. They are **not production code to copy directly**. The single file `Sara Sheila Console.dc.html` is a "Design Component": custom `<x-dc>` / `<sc-for>` / `<sc-if>` markup driven by an inline `class Component` and a runtime (`support.js`). **Do not ship this file or its runtime.**

The task is to **recreate these designs in the target codebase's existing environment** — the real app is a Python/FastAPI backend serving server-rendered HTML (`src/ui/*.html`) styled with plain CSS custom properties and vanilla JS + `fetch`/`EventSource`. Reuse those patterns (or the codebase's chosen framework) and its existing components; the HTML here just documents the target.

## Fidelity
**Mid-fidelity.** Layout, structure, flow, real labels, realistic sample data, and the exact color/type tokens (lifted from the real repo) are all specified and should be matched. It is *not* pixel-perfect — spacing/padding values below are the prototype's; treat them as close guidance and align to the codebase's existing spacing scale where one exists. Wire behavior to real backend endpoints (listed under each view).

## Design Tokens
Lifted verbatim from the real UI (`src/ui/monitor.html`, `src/ui/sheila.html` `:root`):

**Colors**
- `--bg` page background: `#d2b48c`
- `--surface` panels / bars: `#dfc99e`
- `--surface2` inset fields, tracks, code chips: `#ecddb8`
- `--border`: `#c09060`
- `--text`: `#111111`
- `--text2` (muted labels): `#6b5040`
- `--accent` (primary / links / active): `#4a5bc8`  · hover `#3040a0`
- `--red` (BLOCK / critical / HIGH severity rule): `#c0392b`  · soft bg `rgba(192,57,43,.15)`
- `--orange` (ESCALATE / high severity / MED rule): `#c07800`  · soft bg `rgba(192,120,0,.15)`
- `--yellow` (FORWARD→Sheila): `#8a6800`  · soft bg `rgba(138,104,0,.15)`
- `--blue` (FLAG / medium severity): `#2563b0`  · soft bg `rgba(37,99,176,.15)`
- `--green` (PASS / online / caught): `#1a7a3a`  · soft bg `rgba(26,122,58,.15)`
- accent soft badge bg: `rgba(74,91,200,.2)`
- row divider: `rgba(192,144,96,.3)`
- dark code block: bg `#2b2418`, text `#dfc99e`

**Typography**
- Font family (mono): `'SF Mono','Cascadia Code','Fira Code','JetBrains Mono',monospace`
- Body 13px / line-height 1.5
- Section eyebrow labels: 10px, weight 600, `letter-spacing:.10em`, uppercase, color `--text2`
- Panel titles (real): 11px, weight 600, `letter-spacing:.06em`, uppercase, `--text2`
- Stat values: 22–28px, weight 700
- Table header cells: 10px uppercase `--text2`; body cells 11–12px

**Radii / borders / spacing**
- Radius: cards/panels `8–10px`, buttons/inputs `7–8px`, chips/badges `4–6px`
- Panel border: `1px solid #c09060`
- Panel padding: ~`18–22px`; console body padding ~`20–24px`
- Grid gaps: `12–16px`

## Screens / Views

### Global shell
- **Top bar** (`--surface`, bottom border `--border`): left = brand **"Arena"** (19px, weight 700). Center = three inline stats `RULES 12` · `VIOLATIONS 24H 34` · `CATEGORIES 7` (10px uppercase `--text2`, value colored: violations in `--red`). Right = two section pills: **SARA** (`classifying agent`) and **SHEILA** (`red-team agent`); active pill filled `--accent` white text, inactive outlined `--border`.
- Real header equivalent uses `⬡ Sara <badge>` + a `<nav>` of links: Researcher · Admin · SaraBox · | · Monitor · Sheila · ZK Trail · DPO · Red Team. If matching the real app, keep that nav; this prototype simplified it to two section pills.
- **Sara sub-nav** (`--surface`-ish bar): text tabs `Overview · Classify · Policy Rules · Monitor Violations`; active tab = `--text` weight 700 with a 2px `--accent` bottom border, inactive = `--text2` weight 500.

### 1. Overview (Sara section, `tab=overview`)
- **Purpose**: both agents at a glance.
- **Layout**: 4-up stat card grid → 2-up agent cards → full-width activity list. Max width ~1180px, centered.
- **Stat cards**: ACTIVE RULES `12`, VIOLATIONS 24H `34` (value `--red`), AVG CONFIDENCE `0.86`, SHEILA ATTACKS 24H `128`.
- **Sara card**: header "SARA · classifying agent" + online dot (`--green`) "ONLINE". 2×2 stat rows (Active rules 12, Categories 7, Avg confidence 0.86, Violations 24h 34). Dashed divider → "TOP WEAK SPOT": chip `credential_extraction` (red soft bg) + "F1 0.54" + link "→ Policy Rules".
- **Sheila card**: header "SHEILA · red-team agent" + `--orange` dot "RUNNING". 2×2 rows (Active bounties 3, Attacks 24h 128, Bypasses found 9 [red], Catch rate 93% [green]). Divider → "LATEST BYPASS": chip `jailbreak` (orange soft) + "demo-model" + link "→ Attack Runner".
- **Recent activity**: rows with a colored 8px square marker + text + right-aligned meta. Marker colors: violation `--red`, rule `--accent`, attack `--orange`, ok `--green`.

### 2. Classify (Sara section, `tab=classify`)
- **Purpose**: classify a message / session transcript.
- **Layout**: two equal columns.
- **Left ("CLASSIFY CONTENT")**: textarea (200px tall) "Paste a message, prompt, or session transcript…"; row of `Classify` (primary `--accent`) + "or" + `session id…` input.
- **Right ("CLASSIFICATION RESULT")**: verdict badge `VIOLATION` (red soft) + "matched 1 active rule". Field rows: Category chip `identity_access_probing` (accent soft); Confidence `0.91` with a horizontal bar (track `--surface2`, fill `--accent`, width = confidence %); Severity `HIGH` (red soft); Suggested action `ALERT` (orange soft); dashed divider → "MATCHED RULE" link to the rule.
- **Backend**: real classifier lives in `src/safety/classifier.py` / `src/safety/tee_classifier.py`; taxonomy has 7 categories.

### 3. Policy Rules (Sara section, `tab=rules`) — the core flow
- **Purpose**: search existing rules + create/validate a rule.
- **Layout**: split view, `grid-template-columns: 440px 1fr`, plus a full-width **Vertical Rule Packs** strip spanning both columns below.
- **Left panel**: header "POLICY RULES" + `+ New Rule` (primary) → clears selection to show the creator. Search input "Search rules by description…" (filters list by name). Filter chips: `All · identity · credential · injection · spam · self_harm` (active = filled `--accent`). Rule rows: 2-line-clamped name + category chip + severity badge + right-aligned status (`ACTIVE` green / `INACTIVE` muted). Selected row = `--surface2` bg, `--accent` border.
- **Right panel — two modes**:
  - *New rule* (when nothing selected): eyebrow "RULE CREATOR — NEW RULE"; mode toggle **Assisted (NL)** / **Raw SML** (active filled accent); textarea "Describe the policy rule in plain English" (placeholder e.g. *"User should not elicit another user's private address info"*); 2×2 field grid: Category (select), Severity (HIGH/MED/LOW), Action (ALERT/BLOCK/FLAG), Threshold (range 0–1 step .05, default .75, `accent-color:--accent`); buttons `Save Rule` (primary) + `Validate` (ghost).
  - *Rule detail / validation* (when a row is selected): eyebrow "RULE DETAIL · VALIDATION" + right status "VALIDATED · 0 ERRORS" (green dot); rule name; meta chips (category / severity / action / `threshold 0.xx`); "COMPILED SML" dark code block (`#2b2418`) showing the SML; 2-up stat cards MATCHED 24H + STATUS; buttons `Edit` (ghost, reopens creator) + `Deactivate` (red-outlined ghost).
- **Vertical Rule Packs** (full-width strip): eyebrow + description "Pre-compiled rule packs for regulated verticals. Installing copies the pack's rules in as editable policy rules." Then 3 cards (Insurance 14 rules, Healthcare 19, Financial 22), each with name + rule count + description + `Install pack` (ghost, full-width).
- **Sample rules** (name · category · severity · action · threshold):
  1. "Do not allow inquirer to elicit a user's private address or location" · identity_access_probing · HIGH · ALERT · 0.75 · active · matched 41
  2. "Block attempts to extract API keys, tokens or credentials" · credential_extraction · HIGH · BLOCK · 0.80 · active · matched 12
  3. "Flag attempts to override or jailbreak system instructions" · prompt_injection · MED · FLAG · 0.65 · active · matched 63
  4. "Detect coordinated spam via near-duplicate templated posts" · spam_coordination · MED · FLAG · 0.60 · inactive
  5. "Prevent sharing of self-harm methods or instructions" · self_harm · HIGH · BLOCK · 0.85 · active · matched 3
- **Backend**: rules are Osprey `.sml` files — see `src/osprey/policy.py`, `src/osprey_ui/compiler.py`, `src/osprey_ui/vertical_defaults.py`. Tools: `osprey.listRuleFiles / readRuleFile / saveRule / validateRules`.

### 4. Monitor Violations (Sara section, `tab=violations`) — real "Live Verdicts"
- **Purpose**: live feed of Osprey monitor events / verdicts.
- **Layout**: 4 summary cards → single wide table panel.
- **Summary cards**: TOTAL 24H `34` · BLOCKED `12` (red) · ESCALATED `5` (orange) · FWD → SHEILA `7` (yellow).
- **Filter bar**: Action select (All actions / Block / Escalate / Forward → Sheila / Flag / Pass), Severity select, "Rule ID filter…" input, time-range select (Last 24h / 7d), `Refresh` (ghost).
- **Table columns** (grid `88px 104px 1fr 92px 130px 108px`): **TIME · ACTION · RULE · SEVERITY · ATLAS TACTIC · PROOF ID**.
  - ACTION badges: `BLOCK` (red), `ESCALATE` (orange), `FORWARD` (yellow), `FLAG` (blue), `PASS` (green) — colored text on matching soft bg.
  - SEVERITY colored text, capitalized: critical `--red`, high `--orange`, medium `--blue`, low `--text2`.
  - ATLAS TACTIC = MITRE ATLAS id (e.g. `AML.T0051`), PROOF ID = on-chain attestation hash (e.g. `0x8f2a1c…`).
- **Backend**: `GET /osprey/monitor/events/{orgId}?limit=50` + SSE `/monitor/stream`. Real event → verdict mapping: `action_taken` STOP→block, ALERT→flag, LOG→pass; `matched_rule_id`→rule; `erc8004_tx_hash`→proof id. Severity/ATLAS tactic are not on raw events (render "—"). See `src/ui/monitor.html`, `src/safety/monitor.py`, `src/osprey_ui/monitor.py`.

### 5. Sheila — Attack Runner + Bounty Arena (Sheila section)
- **Purpose**: pick a bounty and run adversarial attacks; or create a new bounty.
- **Layout**: `grid-template-columns: 360px 1fr`.
- **Left ("ACTIVE BOUNTIES")**: header with `+ New Bounty` button (primary) → opens Create Bounty in the right column. Filter chips `All · jailbreak · pii_extraction · prompt_injection`. Bounty cards: model name (bold) + reward (green, e.g. `≤ $500`) + category chips. Selected card = `--surface2` bg + `--accent` border.
  - Sample bounties: `demo-model` ≤ $500 [prompt_injection, jailbreak, pii_extraction]; `support-bot-v2` ≤ $300 [pii_extraction]; `moderation-llm` ≤ $750 [jailbreak, prompt_injection].
- **Right — two modes** (`sheilaView`):
  - *Attack (default)* — **SUBMIT ATTACK** panel: TARGET summary (selected model + reward); "Attack prompts (one per line, 1–50)" textarea; char/line counter; 2-up **Your EVM wallet address** (`0x…`) + **Commitment hash · SHA3-256** (readonly field + `Compute` button); `Run Attack` (primary). Then **RESULTS · SARA VERDICT** panel: rows with a fixed-width verdict badge `CAUGHT` (green) / `BYPASSED` (red) + prompt + category chip + confidence; footer "Bypasses surface as weak spots in Sara → Policy Rules" (link).
  - *Create Bounty* (`sheilaView=create`) — **NEW BOUNTY** panel with `Cancel`. **"Add a bounty by"** = three source chips (the *new ways to add*): **Blank**, **Clone selected**, **Template pack** (active filled accent); a hint line describes the chosen source. Form: Target model name (placeholder switches to `demo-model (copy)` when cloning), Target model endpoint (`https://…`), **Attack categories** multi-select chips (`prompt_injection, jailbreak, pii_extraction, treasury_manipulation, governance_attack, identity_confusion` — tap to toggle; Clone/Template prefill a set), Reward pool · USDC, Max payout / finding (default 10), Funder wallet (`0x…`), Expires (7 days / 30 days / No expiry). `Fund & Publish` (primary) + note "Escrows pool on-chain · released per verified finding".
- **Backend / data model** (`src/arena/models.py`): `Bounty{ funder_wallet, target_model_name, target_model_endpoint, categories[], pool_usdc, remaining_usdc, max_payout_per_finding (default 10), expires_at?, status }`; `Submission{ bounty_id, teamer_wallet, prompts[AttackPrompt{prompt,category,technique}], commitment_hash (SHA3-256 of canonical prompts JSON) }`. Bounty tools: `bounty.list / bounty.get / bounty.taxonomy`. Commitment hashing: `src/crypto/commitment.py`, `src/crypto/canonical.py`. The real Sheila "Judge" view (`src/ui/sheila.html`) additionally shows a verdict table (Time/Mode/Decision/Category/Confidence/Attestation/CoT), a confidence-distribution histogram, category-recall bars, and an attestation-verify modal (`GET /sheila/verify/{attId}`) — not rebuilt in this prototype but worth carrying over.

## Interactions & Behavior
- **Section & tab switching**: pure client state; no route change in the prototype. In the real app these are separate pages (`/monitor`, `/sheila`, dashboard tabs) — wire to your router.
- **Policy Rules**: typing in search filters the list live (case-insensitive substring on rule name); clicking a category chip filters by category; clicking a rule selects it (right panel → detail); `+ New Rule` / `Edit` → creator; mode toggle switches NL vs SML editor.
- **Create Bounty**: `+ New Bounty` → create view; source chips change prefilled model name + preselected categories + hint; category chips toggle membership; `Cancel` → attack view.
- **No animations** beyond a subtle new-row highlight in the real monitor (`@keyframes highlight` — accent-tinted bg fading to transparent over .8s on newly streamed rows). Add if you rebuild the SSE feed.
- **Hover**: buttons darken (accent → `#3040a0`); table rows get `rgba(0,0,0,.04)` bg in the real UI.

## State Management
- `section`: `'sara' | 'sheila'`
- `tab` (Sara): `'overview' | 'classify' | 'rules' | 'violations'`
- `selectedRule`: rule id or `null` (null ⇒ new-rule creator)
- `ruleMode`: `'nl' | 'sml'`; `ruleQuery`: search string; `ruleFilter`: category or `'all'`
- `sheilaFilter`: bounty category filter; `selectedBounty`: bounty id
- `sheilaView`: `'attack' | 'create'`; `bountySrc`: `'blank' | 'clone' | 'template'`; `newCats`: string[] of selected categories
- Data fetching (real app): rules via Osprey rule-file tools; violations via `/osprey/monitor/events` + `/monitor/stream` SSE; bounties via `bounty.list`; verdicts via `/api/sheila/verdicts`.

## Assets
- No image assets. The real header uses a `⬡` glyph before the brand; this prototype uses a plain wordmark. Font is a monospace stack (no web font required if the system fonts are present; the prototype loads JetBrains Mono as a fallback).

## Screenshots
Reference renders of each view (in `screenshots/`):
- `01-overview.png` — Overview (both agents at a glance)
- `02-classify.png` — Sara · Classify
- `03-policy-rules.png` — Sara · Policy Rules (split view + rule detail/validation)
- `04-monitor-violations.png` — Sara · Monitor Violations (Live Verdicts)
- `05-sheila-attack-runner.png` — Sheila · Attack Runner + bounties
- `06-sheila-create-bounty.png` — Sheila · Create Bounty flow

## Files
- `Sara Sheila Console.dc.html` — the full prototype (all five views + shell). Design reference only; do not ship.
- `support.js` — the prototype runtime (required only to *open* the HTML locally; not part of the design and not for production).
- Real UI to mirror in-repo: `src/ui/dashboard.html`, `src/ui/monitor.html`, `src/ui/sheila.html`, `src/ui/redteam.html` and their `:root` token blocks.
