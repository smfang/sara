"""
Tests for the A.2-lite Reproducibility Layer.

Covers: canonical.py, hashing.py, reproducibility.py, run_manifest.py.

All tests run without any network, ClickHouse, or LLM calls.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# canonical.py
# ---------------------------------------------------------------------------


class TestCanonicalBytes:
    def test_produces_utf8_bytes(self):
        from src.crypto.canonical import canonical_bytes
        result = canonical_bytes({"schema_version": "1.0", "x": 1})
        assert isinstance(result, bytes)
        result.decode("utf-8")  # must not raise

    def test_keys_sorted(self):
        from src.crypto.canonical import canonical_bytes
        a = canonical_bytes({"schema_version": "1.0", "z": 1, "a": 2})
        b = canonical_bytes({"schema_version": "1.0", "a": 2, "z": 1})
        assert a == b
        parsed = json.loads(a)
        assert list(parsed.keys()) == ["a", "schema_version", "z"]

    def test_no_whitespace(self):
        from src.crypto.canonical import canonical_bytes
        result = canonical_bytes({"schema_version": "1.0", "k": "v"})
        assert b" " not in result
        assert b"\n" not in result

    def test_missing_schema_version_raises(self):
        from src.crypto.canonical import canonical_bytes, NonCanonicalValue
        with pytest.raises(NonCanonicalValue, match="schema_version"):
            canonical_bytes({"k": "v"})

    def test_nested_keys_sorted(self):
        from src.crypto.canonical import canonical_bytes
        a = canonical_bytes({"schema_version": "1.0", "inner": {"z": 1, "a": 2}})
        b = canonical_bytes({"schema_version": "1.0", "inner": {"a": 2, "z": 1}})
        assert a == b

    def test_identical_across_calls(self):
        from src.crypto.canonical import canonical_bytes
        obj = {"schema_version": "1.0", "foo": "bar", "n": 42}
        assert canonical_bytes(obj) == canonical_bytes(obj)

    def test_unknown_type_raises(self):
        from src.crypto.canonical import canonical_bytes, NonCanonicalValue
        class Weird:
            pass
        with pytest.raises(NonCanonicalValue, match="Unrecognised type"):
            canonical_bytes({"schema_version": "1.0", "x": Weird()})


class TestDecimalEncoding:
    def test_decimal_to_micro(self):
        from src.crypto.canonical import canonical_bytes
        result = json.loads(canonical_bytes({"schema_version": "1.0", "amount": Decimal("1.23")}))
        assert result["amount"] == 1_230_000

    def test_decimal_zero(self):
        from src.crypto.canonical import canonical_bytes
        result = json.loads(canonical_bytes({"schema_version": "1.0", "amount": Decimal("0")}))
        assert result["amount"] == 0

    def test_decimal_large(self):
        from src.crypto.canonical import canonical_bytes
        result = json.loads(canonical_bytes({"schema_version": "1.0", "amount": Decimal("999.999999")}))
        assert result["amount"] == 999_999_999

    def test_decimal_too_precise_raises(self):
        from src.crypto.canonical import canonical_bytes, NonCanonicalValue
        with pytest.raises(NonCanonicalValue, match="exact integer"):
            canonical_bytes({"schema_version": "1.0", "amount": Decimal("1.1234567")})


class TestFloatEncoding:
    def test_float_fixed_six_dp(self):
        from src.crypto.canonical import canonical_bytes
        result = json.loads(canonical_bytes({"schema_version": "1.0", "score": 0.9}))
        assert result["score"] == "0.900000"

    def test_float_pi(self):
        from src.crypto.canonical import canonical_bytes
        import math
        result = json.loads(canonical_bytes({"schema_version": "1.0", "score": math.pi}))
        assert result["score"] == "3.141593"

    def test_nan_raises(self):
        from src.crypto.canonical import canonical_bytes, NonCanonicalValue
        with pytest.raises(NonCanonicalValue, match="Non-finite"):
            canonical_bytes({"schema_version": "1.0", "score": float("nan")})

    def test_inf_raises(self):
        from src.crypto.canonical import canonical_bytes, NonCanonicalValue
        with pytest.raises(NonCanonicalValue, match="Non-finite"):
            canonical_bytes({"schema_version": "1.0", "score": float("inf")})

    def test_negative_inf_raises(self):
        from src.crypto.canonical import canonical_bytes, NonCanonicalValue
        with pytest.raises(NonCanonicalValue, match="Non-finite"):
            canonical_bytes({"schema_version": "1.0", "score": float("-inf")})


class TestDatetimeEncoding:
    def test_aware_utc_datetime(self):
        from src.crypto.canonical import canonical_bytes
        dt = datetime(2026, 6, 16, 12, 0, 0, 123456, tzinfo=timezone.utc)
        result = json.loads(canonical_bytes({"schema_version": "1.0", "ts": dt}))
        assert result["ts"] == "2026-06-16T12:00:00.123456Z"

    def test_aware_non_utc_converted(self):
        from src.crypto.canonical import canonical_bytes
        tz_plus5 = timezone(timedelta(hours=5))
        dt = datetime(2026, 6, 16, 17, 0, 0, 0, tzinfo=tz_plus5)
        result = json.loads(canonical_bytes({"schema_version": "1.0", "ts": dt}))
        assert result["ts"] == "2026-06-16T12:00:00.000000Z"

    def test_naive_datetime_raises(self):
        from src.crypto.canonical import canonical_bytes, NonCanonicalValue
        with pytest.raises(NonCanonicalValue, match="Naive datetime"):
            canonical_bytes({"schema_version": "1.0", "ts": datetime(2026, 1, 1)})


class TestBytesEncoding:
    def test_bytes_base64url(self):
        from src.crypto.canonical import canonical_bytes
        result = json.loads(canonical_bytes({"schema_version": "1.0", "data": b"\xff\xfe"}))
        assert result["data"] == "__4"  # base64url of \xff\xfe, no padding

    def test_bytes_empty(self):
        from src.crypto.canonical import canonical_bytes
        result = json.loads(canonical_bytes({"schema_version": "1.0", "data": b""}))
        assert result["data"] == ""


class TestDigest:
    def test_returns_hex_string(self):
        from src.crypto.canonical import digest
        h = digest({"k": "v"})
        assert isinstance(h, str)
        assert len(h) == 64
        int(h, 16)  # must be valid hex

    def test_injects_schema_version(self):
        from src.crypto.canonical import digest, SCHEMA_VERSION
        h1 = digest({"k": "v"})
        h2 = digest({"k": "v", "schema_version": SCHEMA_VERSION})
        assert h1 == h2

    def test_stable_across_calls(self):
        from src.crypto.canonical import digest
        obj = {"alpha": 0.4, "beta": 0.3, "label": "test"}
        assert digest(obj) == digest(obj)

    def test_changes_with_value(self):
        from src.crypto.canonical import digest
        h1 = digest({"score": 0.9})
        h2 = digest({"score": 0.91})
        assert h1 != h2

    def test_stable_across_fresh_interpreter(self):
        """Hash must match a pinned golden value across interpreter restarts."""
        # Golden value computed once and pinned — any change to canonical.py
        # that alters the output will break this test (intentional).
        GOLDEN = "7d69ad2faae3fd990900fcdf7ed8c138c46e6640dd9b280340be83e585c52d4e"
        code = (
            "from src.crypto.canonical import digest; "
            "print(digest({'score': 0.5, 'label': 'repro'}))"
        )
        result = subprocess.check_output(
            [sys.executable, "-c", code], cwd=Path(__file__).parent.parent
        ).decode().strip()
        assert result == GOLDEN, f"canonical hash changed: got {result}, expected {GOLDEN}"


# ---------------------------------------------------------------------------
# hashing.py
# ---------------------------------------------------------------------------


class TestHashInput:
    def test_returns_hex_string(self):
        from src.crypto.hashing import hash_input
        h = hash_input("hello")
        assert isinstance(h, str)
        assert len(h) == 64
        int(h, 16)

    def test_stable(self):
        from src.crypto.hashing import hash_input
        assert hash_input("test prompt") == hash_input("test prompt")

    def test_different_inputs_different_hash(self):
        from src.crypto.hashing import hash_input
        assert hash_input("prompt A") != hash_input("prompt B")

    def test_no_raw_prompt_in_output(self):
        """GDPR: the hash reveals nothing about the original text."""
        from src.crypto.hashing import hash_input
        raw = "sensitive user message containing PII"
        h = hash_input(raw)
        assert raw not in h
        assert "sensitive" not in h
        assert "PII" not in h

    def test_hash_bytes_variant(self):
        from src.crypto.hashing import hash_bytes
        h = hash_bytes(b"\x00\x01\x02")
        assert len(h) == 64


# ---------------------------------------------------------------------------
# reproducibility.py
# ---------------------------------------------------------------------------


def _make_bundle(**overrides) -> "ReproducibilityBundle":
    from src.crypto.reproducibility import ReproducibilityBundle
    defaults = dict(
        schema_version="1.0",
        corpus_version="v2.0.0",
        suite_version="v1.3.0",
        judge_model_id="claude-opus-4-6",
        judge_prompt_hash="a" * 64,
        sheila_seed=42,
        osprey_rules_version="v3.0.0",
        agent_card_version="v1.0.0",
    )
    defaults.update(overrides)
    return ReproducibilityBundle(**defaults)


class TestReproducibilityBundle:
    def test_create_hashes_prompt(self):
        from src.crypto.reproducibility import ReproducibilityBundle
        from src.crypto.hashing import hash_input
        raw_prompt = "You are Sheila, a safety judge..."
        bundle = ReproducibilityBundle.create(
            corpus_version="v2.0.0",
            suite_version="v1.3.0",
            judge_model_id="claude-opus-4-6",
            judge_prompt=raw_prompt,
            sheila_seed=42,
            osprey_rules_version="v3.0.0",
            agent_card_version="v1.0.0",
        )
        assert bundle.judge_prompt_hash == hash_input(raw_prompt)
        assert raw_prompt not in str(bundle)

    def test_round_trip_dict(self):
        from src.crypto.reproducibility import ReproducibilityBundle
        bundle = _make_bundle()
        assert ReproducibilityBundle.from_dict(bundle.to_dict()) == bundle

    def test_frozen(self):
        bundle = _make_bundle()
        with pytest.raises((AttributeError, TypeError)):
            bundle.sheila_seed = 99  # type: ignore


class TestBundleHash:
    def test_stable(self):
        from src.crypto.reproducibility import bundle_hash
        b = _make_bundle()
        assert bundle_hash(b) == bundle_hash(b)

    def test_stable_across_fresh_interpreter(self):
        """Bundle hash must match a pinned golden value — catches any encoding regression."""
        GOLDEN = "62babb2d7601ab60eef31ce02738cce8e27d952e19d45ca7155e3c78361ae9a1"
        code = (
            "from src.crypto.reproducibility import ReproducibilityBundle, bundle_hash; "
            "b = ReproducibilityBundle("
            "schema_version='1.0', corpus_version='v1', suite_version='v1', "
            "judge_model_id='m', judge_prompt_hash='a'*64, sheila_seed=1, "
            "osprey_rules_version='v1', agent_card_version='v1'); "
            "print(bundle_hash(b))"
        )
        result = subprocess.check_output(
            [sys.executable, "-c", code], cwd=Path(__file__).parent.parent
        ).decode().strip()
        assert result == GOLDEN, f"bundle_hash changed: got {result}, expected {GOLDEN}"

    def test_changes_when_any_field_changes(self):
        from src.crypto.reproducibility import bundle_hash
        base = _make_bundle()
        for field, new_val in [
            ("corpus_version", "v3.0.0"),
            ("judge_model_id", "claude-haiku-4-5"),
            ("sheila_seed", 99),
            ("osprey_rules_version", "v4.0.0"),
        ]:
            modified = _make_bundle(**{field: new_val})
            assert bundle_hash(base) != bundle_hash(modified), f"hash unchanged after modifying {field}"


class TestVerifyBundle:
    def test_correct_hash_passes(self):
        from src.crypto.reproducibility import bundle_hash, verify_bundle
        b = _make_bundle()
        assert verify_bundle(b, bundle_hash(b)) is True

    def test_wrong_hash_fails(self):
        from src.crypto.reproducibility import verify_bundle
        b = _make_bundle()
        assert verify_bundle(b, "0" * 64) is False

    def test_tampered_bundle_fails(self):
        from src.crypto.reproducibility import bundle_hash, verify_bundle
        original = _make_bundle()
        expected = bundle_hash(original)
        tampered = _make_bundle(sheila_seed=999)
        assert verify_bundle(tampered, expected) is False


class TestDeriveRunId:
    def test_deterministic(self):
        from src.crypto.reproducibility import derive_run_id
        b = _make_bundle()
        dt = datetime(2026, 6, 16, 10, 0, 0, tzinfo=timezone.utc)
        assert derive_run_id(b, 1, dt) == derive_run_id(b, 1, dt)

    def test_changes_with_round(self):
        from src.crypto.reproducibility import derive_run_id
        b = _make_bundle()
        dt = datetime(2026, 6, 16, 10, 0, 0, tzinfo=timezone.utc)
        assert derive_run_id(b, 1, dt) != derive_run_id(b, 2, dt)

    def test_changes_with_bundle(self):
        from src.crypto.reproducibility import derive_run_id
        b1 = _make_bundle(sheila_seed=1)
        b2 = _make_bundle(sheila_seed=2)
        dt = datetime(2026, 6, 16, 10, 0, 0, tzinfo=timezone.utc)
        assert derive_run_id(b1, 1, dt) != derive_run_id(b2, 1, dt)

    def test_changes_with_started_at(self):
        from src.crypto.reproducibility import derive_run_id
        b = _make_bundle()
        dt1 = datetime(2026, 6, 16, 10, 0, 0, tzinfo=timezone.utc)
        dt2 = datetime(2026, 6, 16, 11, 0, 0, tzinfo=timezone.utc)
        assert derive_run_id(b, 1, dt1) != derive_run_id(b, 1, dt2)

    def test_naive_datetime_raises(self):
        from src.crypto.reproducibility import derive_run_id
        from src.crypto.canonical import NonCanonicalValue
        b = _make_bundle()
        with pytest.raises(NonCanonicalValue, match="Naive datetime"):
            derive_run_id(b, 1, datetime(2026, 1, 1))  # naive — no tzinfo


class TestRewardSampleMetadata:
    def test_make_reward_metadata(self):
        from src.crypto.reproducibility import make_reward_metadata, derive_run_id
        b = _make_bundle()
        dt = datetime(2026, 6, 16, 10, 0, 0, tzinfo=timezone.utc)
        meta = make_reward_metadata(b, training_round=3, started_at=dt)
        assert meta.run_id == derive_run_id(b, 3, dt)
        assert meta.judge_model_id == b.judge_model_id
        assert meta.sheila_seed == b.sheila_seed
        assert meta.training_round == 3


# ---------------------------------------------------------------------------
# run_manifest.py
# ---------------------------------------------------------------------------


def _make_manifest(**overrides):
    from src.crypto.run_manifest import RunManifest, reward_config_hash
    from src.crypto.reproducibility import derive_run_id

    b = _make_bundle()
    dt = datetime(2026, 6, 16, 10, 0, 0, tzinfo=timezone.utc)
    run_id = derive_run_id(b, 1, dt)
    rcfg = {"alpha": 0.4, "beta": 0.3, "gamma": 0.2, "delta": 0.1}
    defaults = dict(
        run_id=run_id,
        reproducibility_bundle=b,
        reward_config_hash=reward_config_hash(rcfg),
        dataset_version="v2.1.0",
        base_model_id="Qwen/Qwen2.5-7B-Instruct",
        lora_rank=64,
        stage="dpo",
        created_at=dt,
    )
    defaults.update(overrides)
    return RunManifest(**defaults)


class TestRunManifest:
    def test_valid_stages_accepted(self):
        for stage in ("sft", "dpo", "rlvr", "grpo"):
            m = _make_manifest(stage=stage)
            assert m.stage == stage

    def test_invalid_stage_raises(self):
        with pytest.raises(ValueError, match="stage"):
            _make_manifest(stage="unsupported")

    def test_naive_created_at_raises(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            _make_manifest(created_at=datetime(2026, 1, 1))

    def test_round_trip_dict(self):
        from src.crypto.run_manifest import RunManifest
        m = _make_manifest()
        assert RunManifest.from_dict(m.to_dict()) == m

    def test_round_trip_file(self, tmp_path):
        from src.crypto.run_manifest import write, load
        m = _make_manifest()
        path = tmp_path / "manifest.json"
        write(m, path)
        loaded = load(path)
        assert loaded == m

    def test_written_file_is_valid_json(self, tmp_path):
        from src.crypto.run_manifest import write
        m = _make_manifest()
        path = tmp_path / "manifest.json"
        write(m, path)
        with open(path) as f:
            data = json.load(f)
        assert data["stage"] == "dpo"
        assert "schema_version" in data

    def test_identical_inputs_produce_identical_files(self, tmp_path):
        from src.crypto.run_manifest import write
        m = _make_manifest()
        p1 = tmp_path / "m1.json"
        p2 = tmp_path / "m2.json"
        write(m, p1)
        write(m, p2)
        assert p1.read_text() == p2.read_text()

    def test_manifest_hash_stable(self):
        m = _make_manifest()
        assert m.manifest_hash() == m.manifest_hash()

    def test_write_creates_parent_dirs(self, tmp_path):
        from src.crypto.run_manifest import write
        m = _make_manifest()
        deep = tmp_path / "a" / "b" / "c" / "manifest.json"
        write(m, deep)
        assert deep.exists()


class TestRewardConfigHash:
    def test_returns_hex(self):
        from src.crypto.run_manifest import reward_config_hash
        h = reward_config_hash({"alpha": 0.4, "beta": 0.3, "gamma": 0.2, "delta": 0.1})
        assert len(h) == 64
        int(h, 16)

    def test_stable(self):
        from src.crypto.run_manifest import reward_config_hash
        cfg = {"alpha": 0.4, "beta": 0.3}
        assert reward_config_hash(cfg) == reward_config_hash(cfg)

    def test_changes_when_weight_changes(self):
        from src.crypto.run_manifest import reward_config_hash
        cfg1 = {"alpha": 0.4, "beta": 0.3, "gamma": 0.2, "delta": 0.1}
        cfg2 = {"alpha": 0.5, "beta": 0.3, "gamma": 0.2, "delta": 0.1}
        assert reward_config_hash(cfg1) != reward_config_hash(cfg2)

    def test_changes_when_key_added(self):
        from src.crypto.run_manifest import reward_config_hash
        cfg1 = {"alpha": 0.4}
        cfg2 = {"alpha": 0.4, "guard_threshold": 0.75}
        assert reward_config_hash(cfg1) != reward_config_hash(cfg2)

    def test_two_manifests_same_inputs_compare_equal(self):
        m1 = _make_manifest()
        m2 = _make_manifest()
        assert m1 == m2
        assert m1.reward_config_hash == m2.reward_config_hash


# ---------------------------------------------------------------------------
# GDPR invariant: no raw prompt text in persisted records
# ---------------------------------------------------------------------------


class TestGDPRInvariant:
    def test_bundle_create_stores_only_hash(self):
        from src.crypto.reproducibility import ReproducibilityBundle
        raw_prompt = "You are an LLM judge. Evaluate: THIS_IS_RAW_PII_PROMPT."
        bundle = ReproducibilityBundle.create(
            corpus_version="v1",
            suite_version="v1",
            judge_model_id="model-id",
            judge_prompt=raw_prompt,
            sheila_seed=0,
            osprey_rules_version="v1",
            agent_card_version="v1",
        )
        as_json = json.dumps(bundle.to_dict())
        assert "THIS_IS_RAW_PII_PROMPT" not in as_json
        assert raw_prompt not in as_json

    def test_manifest_stores_no_raw_prompts(self, tmp_path):
        from src.crypto.run_manifest import write
        from src.crypto.reproducibility import ReproducibilityBundle, derive_run_id
        from src.crypto.run_manifest import RunManifest, reward_config_hash as rcfg

        raw_prompt = "SECRET_SYSTEM_PROMPT_WITH_PII_DO_NOT_STORE"
        bundle = ReproducibilityBundle.create(
            corpus_version="v1", suite_version="v1",
            judge_model_id="model", judge_prompt=raw_prompt,
            sheila_seed=0, osprey_rules_version="v1", agent_card_version="v1",
        )
        dt = datetime(2026, 6, 16, 10, 0, 0, tzinfo=timezone.utc)
        m = RunManifest(
            run_id=derive_run_id(bundle, 1, dt),
            reproducibility_bundle=bundle,
            reward_config_hash=rcfg({"alpha": 0.4}),
            dataset_version="v1", base_model_id="model",
            lora_rank=0, stage="sft", created_at=dt,
        )
        path = tmp_path / "manifest.json"
        write(m, path)
        content = path.read_text()
        # The raw prompt must not appear anywhere in the serialised file
        assert raw_prompt not in content, "Raw prompt found in manifest — GDPR violation"
        assert "SECRET_SYSTEM_PROMPT" not in content
        assert "PII" not in content


# ---------------------------------------------------------------------------
# canonical.py — additional edge cases (QA-flagged gaps)
# ---------------------------------------------------------------------------


class TestCanonicalEdgeCases:
    def test_minimum_valid_dict(self):
        """Empty-value dict with only schema_version is valid."""
        from src.crypto.canonical import canonical_bytes
        result = canonical_bytes({"schema_version": "1.0"})
        assert json.loads(result) == {"schema_version": "1.0"}

    def test_none_value_serialises_as_null(self):
        from src.crypto.canonical import canonical_bytes
        result = json.loads(canonical_bytes({"schema_version": "1.0", "x": None}))
        assert result["x"] is None

    def test_bool_serialises_as_json_bool_not_int(self):
        from src.crypto.canonical import canonical_bytes
        raw = canonical_bytes({"schema_version": "1.0", "flag": True, "off": False})
        # JSON booleans must appear as `true`/`false`, not `1`/`0`
        assert b'"flag":true' in raw
        assert b'"off":false' in raw

    def test_decimal_nan_raises(self):
        from src.crypto.canonical import canonical_bytes, NonCanonicalValue
        from decimal import Decimal
        with pytest.raises((NonCanonicalValue, Exception)):
            canonical_bytes({"schema_version": "1.0", "x": Decimal("NaN")})

    def test_list_values_preserved_order(self):
        from src.crypto.canonical import canonical_bytes
        result = json.loads(canonical_bytes({"schema_version": "1.0", "items": [3, 1, 2]}))
        assert result["items"] == [3, 1, 2]

    def test_hashing_routes_through_canonical(self):
        """hashing.sha3_hex must be the same function as canonical.sha3_hex (single source)."""
        from src.crypto.hashing import sha3_hex as h_sha3
        from src.crypto.canonical import sha3_hex as c_sha3
        assert h_sha3 is c_sha3

    def test_non_string_key_raises(self):
        """Non-string Mapping keys must be rejected to preserve canonical sort order."""
        from src.crypto.canonical import canonical_bytes, NonCanonicalValue
        with pytest.raises(NonCanonicalValue, match="Non-string Mapping key"):
            canonical_bytes({"schema_version": "1.0", 42: "bad_key"})  # type: ignore

    def test_nested_non_string_key_raises(self):
        from src.crypto.canonical import canonical_bytes, NonCanonicalValue
        with pytest.raises(NonCanonicalValue, match="Non-string Mapping key"):
            canonical_bytes({"schema_version": "1.0", "inner": {1: "v"}})


# ---------------------------------------------------------------------------
# reproducibility.py — current_bundle() / set_current_bundle() (Spec §6)
# ---------------------------------------------------------------------------


class TestCurrentBundle:
    def setup_method(self):
        # Reset the module-level singleton before each test
        import src.crypto.reproducibility as repro_mod
        repro_mod._current_bundle = None

    def test_current_bundle_raises_before_set(self):
        from src.crypto.reproducibility import current_bundle
        with pytest.raises(RuntimeError, match="set_current_bundle"):
            current_bundle()

    def test_set_and_get_current_bundle(self):
        from src.crypto.reproducibility import set_current_bundle, current_bundle
        b = _make_bundle()
        set_current_bundle(b)
        assert current_bundle() is b

    def test_set_current_bundle_replaces_previous(self):
        from src.crypto.reproducibility import set_current_bundle, current_bundle
        b1 = _make_bundle(sheila_seed=1)
        b2 = _make_bundle(sheila_seed=2)
        set_current_bundle(b1)
        set_current_bundle(b2)
        assert current_bundle() is b2

    def test_make_reward_metadata_uses_current_bundle(self):
        from src.crypto.reproducibility import set_current_bundle, current_bundle, make_reward_metadata
        b = _make_bundle()
        dt = datetime(2026, 6, 16, 10, 0, 0, tzinfo=timezone.utc)
        set_current_bundle(b)
        meta = make_reward_metadata(current_bundle(), training_round=1, started_at=dt)
        assert meta.judge_model_id == b.judge_model_id


# ---------------------------------------------------------------------------
# bundle_hash sensitivity — all fields covered (QA-flagged gap)
# ---------------------------------------------------------------------------


class TestBundleHashSensitivity:
    @pytest.mark.parametrize("field,new_val", [
        ("corpus_version",      "v99.0.0"),
        ("suite_version",       "v99.0.0"),
        ("judge_model_id",      "claude-haiku-4-5"),
        ("judge_prompt_hash",   "b" * 64),
        ("sheila_seed",         9999),
        ("osprey_rules_version","v99.0.0"),
        ("agent_card_version",  "v99.0.0"),
    ])
    def test_hash_changes_when_field_changes(self, field, new_val):
        from src.crypto.reproducibility import bundle_hash
        base = _make_bundle()
        modified = _make_bundle(**{field: new_val})
        assert bundle_hash(base) != bundle_hash(modified), \
            f"bundle_hash did not change when {field!r} was modified"
