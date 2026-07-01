"""
canonical.py — deterministic encoder (RFC 8785 JCS-aligned).

Single source of truth for any hashing in the Sara/Sheila codebase.
All other modules (reproducibility, run_manifest, commitment) call digest()
or canonical_bytes() here — never roll their own json.dumps.

Typed-field rules (the determinism traps):
  Decimal   → integer micro-units (×10⁶); raises NonCanonicalValue if inexact.
  float     → fixed-scale string, 6 decimal places; rejects NaN / Infinity.
  datetime  → RFC 3339 UTC "Z", 6-digit microseconds; rejects naive datetimes.
  bytes     → base64url, no padding.

Schema-version contract:
  Every top-level object passed to digest() receives a "schema_version" field
  injected automatically if absent, so records are self-describing.
  canonical_bytes() enforces the field is present and raises if it is not.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

SCHEMA_VERSION = "1.0"

# Micro-unit scale: 1 unit = 10^6 micro-units (same as USDC micro-cents).
_MICRO_SCALE = Decimal("1000000")


class NonCanonicalValue(ValueError):
    """Raised when a value cannot be encoded canonically."""


# ---------------------------------------------------------------------------
# Core encoder
# ---------------------------------------------------------------------------


def canonical_bytes(obj: Mapping[str, Any]) -> bytes:
    """
    Encode *obj* to canonical UTF-8 bytes.

    Rules:
    - Keys sorted lexicographically at every level.
    - No insignificant whitespace (separators=(',', ':')).
    - Typed-field preprocessing applied recursively.
    - "schema_version" must be present in the top-level mapping.

    Raises NonCanonicalValue for unrepresentable values.
    """
    if "schema_version" not in obj:
        raise NonCanonicalValue(
            "Missing 'schema_version' in mapping passed to canonical_bytes(). "
            "Call digest() instead — it injects schema_version automatically."
        )
    serialisable = _preprocess(obj)
    return json.dumps(serialisable, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha3_hex(data: bytes) -> str:
    """SHA3-256 of raw bytes, returned as a lowercase hex string.

    This is the one place in the codebase that calls hashlib.sha3_256.
    All other modules (hashing.py, reproducibility.py, …) import and
    call this function so the primitive is auditable in one grep.
    """
    return hashlib.sha3_256(data).hexdigest()


def digest(obj: Mapping[str, Any]) -> str:
    """
    SHA3-256 digest of the canonical encoding of *obj*.

    Automatically injects schema_version = SCHEMA_VERSION if absent.
    Returns a lowercase hex string.
    """
    stamped = dict(obj)
    stamped.setdefault("schema_version", SCHEMA_VERSION)
    return sha3_hex(canonical_bytes(stamped))


# ---------------------------------------------------------------------------
# Typed-field preprocessing
# ---------------------------------------------------------------------------


def _preprocess(value: Any) -> Any:
    """Recursively convert types to JSON-safe, canonical representations."""
    if isinstance(value, Mapping):
        for k in value:
            if not isinstance(k, str):
                raise NonCanonicalValue(
                    f"Non-string Mapping key {k!r} (type {type(k).__name__!r}) — "
                    "all keys must be str to guarantee canonical sort order."
                )
        return {k: _preprocess(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_preprocess(v) for v in value]
    if isinstance(value, Decimal):
        return _decimal_to_micro(value)
    if isinstance(value, float):
        return _float_to_string(value)
    if isinstance(value, datetime):
        return _datetime_to_rfc3339(value)
    if isinstance(value, bytes):
        return _bytes_to_base64url(value)
    if isinstance(value, bool):
        return value  # must come before int check (bool is a subclass of int)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return value
    if value is None:
        return None
    raise NonCanonicalValue(f"Unrecognised type {type(value).__name__!r} — add an explicit conversion before calling digest()")


def _decimal_to_micro(d: Decimal) -> int:
    """Convert Decimal to integer micro-units (×10⁶). Raises if inexact."""
    try:
        micro = d * _MICRO_SCALE
        int_micro = int(micro)
        if Decimal(int_micro) != micro:
            raise NonCanonicalValue(
                f"Decimal {d!r} cannot be represented as an exact integer in micro-units "
                f"(×10⁶). Got fractional remainder {micro - int_micro}."
            )
        return int_micro
    except InvalidOperation as exc:
        raise NonCanonicalValue(f"Invalid Decimal {d!r}: {exc}") from exc


def _float_to_string(f: float) -> str:
    """Convert float to a fixed-scale string (6 dp). Rejects NaN and Infinity."""
    if math.isnan(f) or math.isinf(f):
        raise NonCanonicalValue(
            f"Non-finite float {f!r} cannot be canonically encoded. "
            "Use Decimal for monetary values or store as int."
        )
    return f"{f:.6f}"


def _datetime_to_rfc3339(dt: datetime) -> str:
    """
    Convert datetime to RFC 3339 UTC Z with 6-digit microseconds.
    Rejects naive (timezone-unaware) datetimes.
    """
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise NonCanonicalValue(
            f"Naive datetime {dt!r} rejected. Attach timezone.utc before encoding."
        )
    utc = dt.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _bytes_to_base64url(b: bytes) -> str:
    """Encode bytes as base64url with no padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
