#!/usr/bin/env python3
"""Generate the CTEF independence-rubric fixtures with real Ed25519 signatures.

Deterministic: issuer keypairs are derived from fixed 32-byte seeds, so re-running
this script reproduces byte-identical fixtures (including signatures). No clocks,
no randomness — every value is pinned so any party can recompute independently.

Canonicalization + signing follow this repo's CTEF substrate exactly:
  - JCS RFC 8785 via ``rfc8785.dumps`` (same lib src/trust/envelope_v2.py uses).
  - Ed25519 detached compact JWS ``header..sig`` over SHA-256 of the JCS-canonical,
    proof-stripped payload (same construction as envelope_v2.sign_envelope).

Produces, alongside this script (composed/v1/):
  valid-composition.json      — independence holds (drop-A ⇒ composite DENY)
  laundered-authority.json    — NEGATIVE: A's authority laundered into B
                                (drop-A ⇒ composite still PERMIT) — the rubric MUST catch this.

Run:  python3 generate_fixtures.py
Verify: python3 verify.py
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FIX = Path(__file__).parent  # composed/v1/ — fixtures sit alongside this script

# --- Fixed issuer seeds (pinned; NOT production keys — demo material only) ------
SEED_A = bytes(range(32))                       # issuer A — authority
SEED_B = bytes(range(32, 64))                   # issuer B — continuity
KID_A = "did:web:issuer-a.example#key-1"
KID_B = "did:web:issuer-b.example#key-1"

SUBJECT = "did:web:getagentid.dev:agent:independence_demo_001"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwk(pk: Ed25519PrivateKey, kid: str) -> dict:
    raw = pk.public_key().public_bytes_raw()
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw),
            "kid": kid, "use": "sig", "alg": "EdDSA"}


def canonical(payload: dict) -> bytes:
    """JCS RFC 8785 over the proof-stripped payload (matches envelope_v2)."""
    stripped = {k: v for k, v in payload.items() if k != "proof"}
    return rfc8785.dumps(stripped)


def payload_hash(payload: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(payload)).hexdigest()


def sign_slot(slot: dict, priv: Ed25519PrivateKey, kid: str) -> dict:
    """Attach a detached compact JWS proof over SHA-256(JCS(proof-stripped slot))."""
    digest = bytes.fromhex(payload_hash(slot).split(":", 1)[1])
    header = {"alg": "EdDSA", "kid": kid.split("#", 1)[-1], "typ": "JWT"}
    header_b64 = _b64url(rfc8785.dumps(header))
    sig_b64 = _b64url(priv.sign(digest))
    signed = dict(slot)
    signed["proof"] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": kid,
        "jws": f"{header_b64}..{sig_b64}",
    }
    return signed


def slot_a(priv_a: Ed25519PrivateKey) -> dict:
    """Signed CTEF authority attestation: issuer A grants read scope to subject."""
    slot = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://agentgraph.co/ns/trust-evidence/v1",
        ],
        "type": "TrustAttestation",
        "version": "0.3.2",
        "claim_type": "authority",
        "issuer": "did:web:issuer-a.example",
        "subject": {"did": SUBJECT},
        "evidence_basis": {
            "delegation_chain": [
                {
                    "hop": 0,
                    "delegator_did": "did:aps:z6MkHumanPrincipalIndependenceDemo",
                    "delegate_did": SUBJECT,
                    "scope": ["action:read", "resource:documents"],
                    "not_before": "2026-08-01T00:00:00.000Z",
                    "not_after": "2026-11-01T00:00:00.000Z",
                }
            ],
            "evidenceType": "delegation",
        },
        "issued_at": "2026-08-01T00:00:00.000Z",
        "expires_at": "2026-11-01T00:00:00.000Z",
    }
    return sign_slot(slot, priv_a, KID_A)


def slot_b_bound(priv_b: Ed25519PrivateKey, authority_ref: str) -> dict:
    """Signed CTEF continuity attestation, CORRECTLY bound to A via authority_ref.

    B's signed preimage embeds ``authority_ref`` = content-addressed hash of A's
    exact (proof-stripped) preimage. B's continuity claim is only meaningful while
    exercising the authority named by that ref, so B is cryptographically pinned
    to A's specific authorization.
    """
    slot = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://agentgraph.co/ns/trust-evidence/v1",
        ],
        "type": "TrustAttestation",
        "version": "0.3.2",
        "claim_type": "continuity",
        "issuer": "did:web:issuer-b.example",
        "subject": {"did": SUBJECT},
        "evidence_basis": {
            # Content-addressed pointer to A's authorization. Covered by B's sig.
            "authority_ref": authority_ref,
            "session_epoch": 7,
            "rotation_chain_intact": True,
            "evidenceType": "continuity-observation",
        },
        "issued_at": "2026-08-01T00:05:00.000Z",
        "expires_at": "2026-11-01T00:00:00.000Z",
    }
    return sign_slot(slot, priv_b, KID_B)


def slot_b_laundered(priv_b: Ed25519PrivateKey) -> dict:
    """Signed CTEF continuity attestation that LAUNDERS A's authority.

    Instead of binding to A's preimage by content-addressed hash, B inlines a
    self-asserted PLAINTEXT COPY of the granted scope (``granted_scope``) with NO
    authority_ref. B signs its own copy, so a permissive composite that reads the
    inlined scope treats B's word as authoritative — A's signature is decorative.
    Strip A and the composite still permits: authority was laundered.
    """
    slot = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://agentgraph.co/ns/trust-evidence/v1",
        ],
        "type": "TrustAttestation",
        "version": "0.3.2",
        "claim_type": "continuity",
        "issuer": "did:web:issuer-b.example",
        "subject": {"did": SUBJECT},
        "evidence_basis": {
            # NO authority_ref. Self-asserted inline copy of A's grant instead.
            "granted_scope": ["action:read", "resource:documents"],
            "session_epoch": 7,
            "rotation_chain_intact": True,
            "evidenceType": "continuity-observation",
        },
        "issued_at": "2026-08-01T00:05:00.000Z",
        "expires_at": "2026-11-01T00:00:00.000Z",
    }
    return sign_slot(slot, priv_b, KID_B)


def slot_b_copy_bound(priv_b: Ed25519PrivateKey, authority_ref: str) -> dict:
    """Signed CTEF continuity attestation demonstrating the PRAGMATIC-MIDDLE case.

    B inlines a plaintext ``granted_scope`` copy for convenience BUT also carries a
    content-addressed ``authority_ref`` binding it to A's exact preimage. Because the
    copy is accompanied by a resolving binding hash, R4 permits it: a conformant
    verifier reads the ``authority_ref`` (the copy is decorative and never
    authoritative). Drop A and the binding no longer resolves, so independence still
    holds — the copy does not launder anything.
    """
    slot = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://agentgraph.co/ns/trust-evidence/v1",
        ],
        "type": "TrustAttestation",
        "version": "0.3.2",
        "claim_type": "continuity",
        "issuer": "did:web:issuer-b.example",
        "subject": {"did": SUBJECT},
        "evidence_basis": {
            # Convenience copy AND a resolving binding hash. R4 permits this pairing.
            "authority_ref": authority_ref,
            "granted_scope": ["action:read", "resource:documents"],
            "session_epoch": 7,
            "rotation_chain_intact": True,
            "evidenceType": "continuity-observation",
        },
        "issued_at": "2026-08-01T00:05:00.000Z",
        "expires_at": "2026-11-01T00:00:00.000Z",
    }
    return sign_slot(slot, priv_b, KID_B)


def build() -> None:
    FIX.mkdir(exist_ok=True)
    priv_a = Ed25519PrivateKey.from_private_bytes(SEED_A)
    priv_b = Ed25519PrivateKey.from_private_bytes(SEED_B)

    signed_a = slot_a(priv_a)
    authority_ref = payload_hash(signed_a)  # hash of A's proof-stripped preimage

    # ---- valid composition (independence holds) ------------------------------
    valid = {
        "composition_version": "composed-v1",
        "independence_profile": "ctef-independence-v0",
        "subject_did": SUBJECT,
        "issued_at": "2026-08-01T00:10:00.000Z",
        "slots": {
            "authority": signed_a,
            "continuity": slot_b_bound(priv_b, authority_ref),
        },
        "jwks": {KID_A: _jwk(priv_a, KID_A), KID_B: _jwk(priv_b, KID_B)},
        "expected_composite": {
            "decision": "permit",
            "gating_slots": ["authority", "continuity"],
            "reasoning": "Both legs verify; B is content-addressed-bound to A.",
        },
        "expected_independence": {
            "profile": "ctef-independence-v0",
            "drop_authority": {
                "composite": "deny",
                "reason": (
                    "B.evidence_basis.authority_ref names A's preimage hash; with A "
                    "removed the ref cannot be recomputed+verified, so B's dependency "
                    "is unsatisfied. A is load-bearing — independence holds."
                ),
            },
            "rubric_verdict": "PASS",
        },
    }

    # ---- laundered composition (NEGATIVE — rubric MUST FAIL it) --------------
    laundered = {
        "composition_version": "composed-v1",
        "independence_profile": "ctef-independence-v0",
        "subject_did": SUBJECT,
        "issued_at": "2026-08-01T00:10:00.000Z",
        "slots": {
            "authority": signed_a,
            "continuity": slot_b_laundered(priv_b),
        },
        "jwks": {KID_A: _jwk(priv_a, KID_A), KID_B: _jwk(priv_b, KID_B)},
        "expected_composite": {
            "decision": "permit",
            "gating_slots": ["authority", "continuity"],
            "reasoning": (
                "A permissive composite reads B's inlined granted_scope as "
                "authoritative and waves the composition through while A is present."
            ),
        },
        "expected_independence": {
            "profile": "ctef-independence-v0",
            "drop_authority": {
                "composite": "permit",
                "reason": (
                    "B carries a self-asserted plaintext copy of A's scope with NO "
                    "authority_ref binding. Removing A changes nothing the permissive "
                    "composite reads, so it still permits — A's authority was laundered "
                    "into B. Independence is VIOLATED."
                ),
            },
            "rubric_verdict": "FAIL",
            "violated_requirement": (
                "R4 (bare self-asserted grant copy, no binding authority_ref) and "
                "R3 (drop-one-signature ⇒ composite MUST fail)"
            ),
        },
    }

    # ---- copy-with-binding (PRAGMATIC MIDDLE — rubric MUST PASS it) ----------
    # A plaintext granted_scope copy is permitted BECAUSE it is accompanied by a
    # resolving authority_ref. Demonstrates R4's permitted branch (decision 5).
    copy_bound = {
        "composition_version": "composed-v1",
        "independence_profile": "ctef-independence-v0",
        "subject_did": SUBJECT,
        "issued_at": "2026-08-01T00:10:00.000Z",
        "slots": {
            "authority": signed_a,
            "continuity": slot_b_copy_bound(priv_b, authority_ref),
        },
        "jwks": {KID_A: _jwk(priv_a, KID_A), KID_B: _jwk(priv_b, KID_B)},
        "expected_composite": {
            "decision": "permit",
            "gating_slots": ["authority", "continuity"],
            "reasoning": (
                "Both legs verify; B carries a convenience granted_scope copy but "
                "is content-addressed-bound to A via a resolving authority_ref."
            ),
        },
        "expected_independence": {
            "profile": "ctef-independence-v0",
            "drop_authority": {
                "composite": "deny",
                "reason": (
                    "B's authority_ref names A's preimage hash; with A removed the ref "
                    "cannot be recomputed+verified, so B's dependency is unsatisfied. "
                    "The plaintext granted_scope copy is decorative — a conformant "
                    "verifier reads the ref, not the copy. A is load-bearing."
                ),
            },
            "rubric_verdict": "PASS",
            "note": (
                "R4 pragmatic middle: a plaintext grant copy is permitted ONLY when "
                "accompanied by a binding authority_ref that resolves to a present, "
                "verified slot. Strip the authority_ref and this becomes "
                "laundered-authority.json (FAIL)."
            ),
        },
    }

    (FIX / "valid-composition.json").write_text(json.dumps(valid, indent=2) + "\n")
    (FIX / "laundered-authority.json").write_text(json.dumps(laundered, indent=2) + "\n")
    (FIX / "copy-with-binding.json").write_text(json.dumps(copy_bound, indent=2) + "\n")
    print("wrote valid-composition.json")
    print("wrote laundered-authority.json")
    print("wrote copy-with-binding.json")
    print("authority_ref (sha256 of A's JCS preimage):", authority_ref)


if __name__ == "__main__":
    build()
