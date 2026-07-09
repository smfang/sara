"""
Sheila Agent Card + identity (A2A Slice 2).

Builds a signed Agent Card and its did:web DID document, reusing the repo's
ECDSA P-384 signer (`src/crypto/attestation.py`) so identity and evaluation
attestations share one key. Card is bound: card -> did:web -> (stub) ERC-8004.

- `build_agent_card(base_url, signer)` -> signed card dict
- `verify_agent_card(card)` -> bool (self-contained: verifies against the
  public key embedded in the card, recomputing the canonical payload)
- `build_did_document(base_url, signer)` -> did:web DID doc (served at
  /.well-known/did.json so the did:web resolves to this key)

Heavy identity crypto (real ERC-8004 registration, x402-gated calls) is stubbed
with `# A.5-full:` markers behind the same shape.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

from src.crypto.canonical import canonical_bytes

try:
    from src.crypto.attestation import CRYPTO_AVAILABLE
except Exception:  # pragma: no cover
    CRYPTO_AVAILABLE = False

CAPABILITIES = ["judge", "redteam"]
ENDPOINTS = {"judge": "/judge", "redteam": "/redteam/session"}
SKILLS = [
    {"id": "judge", "description": "Evaluate an agent interaction, return a verdict + category."},
    {"id": "redteam", "description": "Run adversarial probes against a target model."},
]


def _did_web(base_url: str) -> str:
    """did:web identifier for a base URL (host, port-encoded per the spec)."""
    netloc = urlparse(base_url).netloc or base_url
    # did:web encodes a ':' in host:port as %3A
    return "did:web:" + netloc.replace(":", "%3A")


def _card_core(base_url: str, did: str) -> dict:
    """The signed portion of the card (everything except the signature)."""
    return {
        "schema_version": 1,   # required by canonical_bytes (RFC 8785 JCS signer)
        "name": "sheila",
        "role": "red-team-judge",
        "protocol": "a2a/0.1",
        "did": did,
        "base_url": base_url.rstrip("/"),
        "capabilities": list(CAPABILITIES),
        "endpoints": dict(ENDPOINTS),
        "skills": list(SKILLS),
        # Identity/interop seams (stubbed):
        "erc8004": {"registry": "", "chain": "base", "tx_hash": ""},  # A.5-full: on-chain register
        "payment": {"scheme": "x402", "endpoint": "/judge"},          # A.5-full: x402-gated calls
        "created_at": "2026-01-01T00:00:00Z",  # fixed so the card/signature are stable
    }


def build_agent_card(base_url: str, signer=None) -> dict:
    """Build a signed Agent Card. If no signer / crypto unavailable, returns the
    card unsigned (`signed: False`) so the service still advertises capabilities."""
    did = _did_web(base_url)
    card = _card_core(base_url, did)

    if signer is None and CRYPTO_AVAILABLE:
        from src.crypto.attestation import AttestationSigner
        try:
            signer = AttestationSigner()
        except Exception:
            signer = None

    if signer is None:
        card["signed"] = False
        card["signature"] = ""
        return card

    card["public_key_pem"] = signer.public_key_pem()
    card["key_id"] = signer.key_id
    card["signature"] = signer.sign_bytes(canonical_bytes(card))
    card["signed"] = True
    return card


def verify_agent_card(card: dict) -> bool:
    """Verify a signed card against the public key embedded in it. Self-contained:
    a third party needs only the card. Returns False on any tamper/missing key."""
    if not card.get("signed") or not card.get("signature") or not card.get("public_key_pem"):
        return False
    if not CRYPTO_AVAILABLE:
        return False
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend

    signature = card["signature"]
    # Must match build_agent_card's signed payload exactly: core + public_key_pem
    # + key_id, i.e. everything EXCEPT the signature and the `signed` flag (both
    # added after signing).
    unsigned = {k: v for k, v in card.items() if k not in ("signature", "signed")}
    try:
        pub = serialization.load_pem_public_key(
            card["public_key_pem"].encode(), backend=default_backend()
        )
        pub.verify(bytes.fromhex(signature), canonical_bytes(unsigned), ec.ECDSA(hashes.SHA384()))
        return True
    except Exception:
        return False


def build_did_document(base_url: str, signer=None) -> dict:
    """did:web DID document exposing the card's verification key + A2A service."""
    did = _did_web(base_url)
    doc = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "service": [{
            "id": f"{did}#a2a",
            "type": "A2A",
            "serviceEndpoint": base_url.rstrip("/"),
        }],
    }
    if signer is None and CRYPTO_AVAILABLE:
        from src.crypto.attestation import AttestationSigner
        try:
            signer = AttestationSigner()
        except Exception:
            signer = None
    if signer is not None:
        doc["verificationMethod"] = [{
            "id": f"{did}#key-1",
            "type": "EcdsaSecp384r1VerificationKey2019",
            "controller": did,
            "publicKeyPem": signer.public_key_pem(),
        }]
        doc["assertionMethod"] = [f"{did}#key-1"]
    return doc
