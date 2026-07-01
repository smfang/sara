"""
hashing.py — GDPR-safe prompt hashing helper.

Mandate (RL-09 / PRD §8 Privacy):
  Any module that logs a prompt, user message, or agent response to
  rl_training.* tables or any other persisted store MUST call hash_input()
  and store only the returned hex digest — never the raw text.

Route all hashing through canonical.py (sha3_256) so the primitive is
always in one place. This file is a thin, named convenience layer that
makes the GDPR intent visible and grep-able.
"""

from __future__ import annotations

# Route all SHA3-256 through canonical.sha3_hex — single source of truth (Sec 8).
from src.crypto.canonical import sha3_hex


def hash_input(text: str) -> str:
    """
    Return the SHA3-256 hex digest of *text*.

    Store this, not the raw text. The digest is one-way; raw text
    cannot be recovered from it, satisfying right-to-erasure requirements.
    """
    return sha3_hex(text.encode("utf-8"))


def hash_bytes(data: bytes) -> str:
    """SHA3-256 hex digest of raw bytes (for binary blobs, model weights, etc.)."""
    return sha3_hex(data)
