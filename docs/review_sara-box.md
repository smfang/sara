# Spec Review — sara-box (Sara in a Box)

_Read-only review against PRD v3 §7. Spec status: Implemented._

**Summary (3 lines)**
- NL org description → skill-configured classifier is present: `SaraBoxServer.build_from_description()` drives a `SkillBuilder` that produces a `SkillFile`, with no per-vertical model fork.
- Taxonomy is a real library keyed by org type (`dao`/`defi`/`nft`), with `DAO_TAXONOMY` as the single source of the 6 DAO leaf ids.
- `tests/test_sarabox.py` passes (part of the 163-test green run).

| Requirement | Status | Evidence (file:line) | Gap | Severity |
|---|---|---|---|---|
| NL org description → skill-configured classifier (no model fork) | PRESENT | `src/sarabox/server.py:137` (`build_from_description`), `:70,77` (`SkillBuilder` injected); classifier configured by skill, not forked | — | — |
| `SkillFile` is the customization layer | PRESENT | `src/sarabox/models.py:26` (`class SkillFile`); `src/sarabox/skill_builder.py` builds it | — | — |
| Taxonomy library, extensible beyond DAO | PRESENT | `src/sarabox/taxonomy.py:138-145` (`get_taxonomy_for_org_type` → `dao`/`defi`/`nft`) | Extensibility is a fixed dict of 3 types, not a registry/plugin; new verticals require code edit | low |
| `DAO_TAXONOMY` single source of 6 leaf ids | PRESENT | `src/sarabox/taxonomy.py:11` (`DAO_TAXONOMY: list[dict]`), referenced as default at `:145` | — | — |

**Gaps (severity-ranked)**
1. **low — taxonomy extensibility is a hardcoded map.** Beyond-DAO support exists (`defi`,`nft`) but adding a vertical means editing `get_taxonomy_for_org_type`. _Action:_ optional — expose a registration hook if third parties are expected to add taxonomies without a code change.

`DECISION: READY (all core rows PRESENT; only a minor extensibility nicety outstanding)`
