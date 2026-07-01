# Spec Review — zk (Cryptographic Audit Trail)

_Read-only review against PRD v3 §7. Spec status: In Progress. Tests: `tests/test_crypto.py`._

**Summary (3 lines)**
- L1 commitment (SHA3-256 + reveal), L2 ECDSA P-384 signing over canonical JSON, `AttestingAgent`, and the `prev_hash` chain are all implemented; `tests/test_crypto.py` passes.
- **The L2 `EvaluationAttestation` field schema DIVERGES materially from the spec's named fields** — only `bounty_id` overlaps; the spec's `attack_success/commitment_hash/coverage_category/judge_model_id/target_model_id/novelty_score/raw_score/payout_usdc/evaluated_at` are replaced by a reward-component schema.
- SP1 L3 proof is gated behind `ZK_PROOF_ENABLED` (default off) as specified.

| Requirement | Status | Evidence (file:line) | Gap | Severity |
|---|---|---|---|---|
| L1 `commitment.py`: SHA3-256 commit + reveal verify | PRESENT | `src/crypto/commitment.py:5-8,44-46` (commit over prompt/response/bounty/salt/timestamp); reveal/verify in module | Commit preimage is `prompt_hash|response_hash|bounty_id|salt|timestamp`, not literally `attack||salt||bounty_id` — stronger, but differs from spec string | low |
| L2 `EvaluationAttestation` dataclass | DIVERGENT | `src/crypto/attestation.py:32-47` | Fields are `attestation_id, commitment_id, bounty_id, sheila_decision, sheila_category, confidence, reward_alpha/beta/gamma/delta, final_score, timestamp_ms, public_key_id, signature` — **not** the spec's 10 named fields | **high** |
| ECDSA P-384 sign()/verify() over canonical JSON (sorted keys) | PRESENT | `attestation.py:77` (`SECP384R1`), `:82` (`sign`), `:92` (`verify`), `:84,96` (`_canonical_payload`) | — | — |
| `AttestingAgent.evaluate_with_attestation()` wired into Sheila judge | PARTIAL | `src/crypto/attesting_agent.py:24,39` (method exists, builds commitment+attestation) | Wiring point exists; not verified that Sheila judge mode actually calls it end-to-end | med |
| `prev_hash` hash-chain; inputs hashed before ClickHouse write | PRESENT | `commitment.py:11,24,38,54` (`prev_hash` chain); `attesting_agent.py:14,55` (store with prev_hash) | GDPR hashing present; actual ClickHouse write path not exercised in unit tests | low |
| SP1 proof stub gated behind `ZK_PROOF_ENABLED` (default false) | PRESENT | `src/crypto/__init__.py:10` (L3 optional, gated on `ZK_PROOF_ENABLED`) | — | — |
| Tests: round-trip, signature verify, tamper, canonical determinism | PRESENT | `tests/test_crypto.py` — passed in the 163-test run | Field-schema mismatch means tests validate the *implemented* schema, not the spec's | med |

**Gaps (severity-ranked)**
1. **high — attestation schema does not match the spec contract.** Any external verifier or ZK circuit built to the PRD's field list (`attack_success`, `commitment_hash`, `coverage_category`, `judge_model_id`, `target_model_id`, `novelty_score`, `raw_score`, `payout_usdc`, `evaluated_at`) will not deserialize the implemented record. _Action:_ reconcile — either update the PRD to the reward-component schema (if that's the intended design) or add the missing fields; whichever is canonical, make one match the other before L3 circuit work depends on it.
2. **med — `evaluate_with_attestation` end-to-end wiring unverified.** The method exists but I found no call site in Sheila judge mode. _Action:_ confirm/add the call in the judge path and add an integration test.
3. **low — L1 commit preimage differs from spec string.** Implementation is broader (adds response/timestamp). _Action:_ update spec wording to match.

`DECISION: NOT-READY (L2 attestation field schema diverges from spec — high-severity contract mismatch to reconcile before L3/verifier work)`
