#!/usr/bin/env python3
"""Generate the CTEF independence-rubric fixtures with real Ed25519 signatures.

Deterministic: issuer keypairs are derived from fixed 32-byte seeds, so re-running
this script reproduces byte-identical fixtures (including signatures). No clocks,
no randomness — every value is pinned so any party can recompute independently.

Canonicalization + signing follow this repo's CTEF substrate exactly:
  - JCS RFC 8785 via ``rfc8785.dumps`` (same lib src/trust/envelope_v2.py uses).
  - Ed25519 detached compact JWS ``header..sig`` over SHA-256 of the JCS-canonical,
    proof-stripped payload (same construction as envelope_v2.sign_envelope).

Produces, alongside this script (composed/v1/independence/):
  valid-composition.json              — independence holds (drop-A ⇒ composite DENY)
  laundered-authority.json            — NEGATIVE: A's authority laundered into B
                                        (drop-A ⇒ composite still PERMIT) — the rubric MUST catch this.
  copy-with-binding.json              — R4 pragmatic middle: plaintext copy PLUS a resolving binding.
  or-composition-scope-boundary.json  — DISJUNCTIVE scope boundary: an honest OR-composition that the
                                        single-slot R3 quantification misfires on (documented FAIL).
  cross-suite-binding.json            — CTEF side of a two-suite composition (Task C); the co-suite leg
                                        binds to this authority by the same content-addressed hash.

`authority_ref` uses this profile's own domain-separation tag,
`recomputable-evidence.independence:v1:`: the binding hash is SHA-256 over that
tag prepended to the referenced slot's JCS preimage. argentum's
`mycelium.action-ref:v2:` tag (tagged/live at commit 96931c9) is the first
implementation of this domain-separation property; see rubric.md §8 item 1. The
Ed25519 signature preimage is unchanged (raw JCS, no tag).

Run:    python3 generate_fixtures.py
Check:  python3 generate_fixtures.py --check   # regenerate + diff, exit nonzero on drift
Verify: python3 verify.py
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FIX = Path(__file__).parent  # composed/v1/ — fixtures sit alongside this script

# --- Fixed issuer seeds (pinned; NOT production keys — demo material only) ------
SEED_A = bytes(range(32))                       # issuer A — authority
SEED_B = bytes(range(32, 64))                   # issuer B — continuity
SEED_C = bytes(range(64, 96))                   # issuer C — second (redundant) authority
KID_A = "did:web:issuer-a.example#key-1"
KID_B = "did:web:issuer-b.example#key-1"
KID_C = "did:web:issuer-c.example#key-1"

SUBJECT = "did:web:getagentid.dev:agent:independence_demo_001"

# This profile's own domain-separation tag for the `authority_ref` binding hash.
# argentum's mycelium.action-ref:v2: tag (tagged/live at commit 96931c9) is the
# first implementation of this domain-separation property; this profile reuses
# the construction under its own, substrate-neutral tag: the binding hash is
# SHA-256 over the tag bytes prepended to the referenced slot's RFC 8785 JCS
# preimage. This is ONLY the content-address used to bind one leg to another;
# the Ed25519 *signature* preimage is unchanged (raw JCS, no tag) so slot signing
# still matches this repo's CTEF substrate.
INDEPENDENCE_TAG = b"recomputable-evidence.independence:v1:"


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
    """Raw SHA-256 of the JCS preimage. This is the SIGNATURE digest (no tag)."""
    return "sha256:" + hashlib.sha256(canonical(payload)).hexdigest()


def binding_hash(payload: dict) -> str:
    """This profile's domain-separated content address, used for `authority_ref`.

    SHA-256( INDEPENDENCE_TAG + JCS(proof-stripped payload) ), 'sha256:'-prefixed
    lowercase hex. Distinct from the raw signature digest above so the tag scopes
    the binding hash without touching how slots are signed.
    """
    return "sha256:" + hashlib.sha256(INDEPENDENCE_TAG + canonical(payload)).hexdigest()


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


def slot_authority_c(priv_c: Ed25519PrivateKey) -> dict:
    """A SECOND, independent authority attestation for the OR-composition fixture.

    Issuer C grants the SAME scope to the SAME subject as issuer A, via its own
    delegation chain from a different human principal. It is self-standing: no
    authority_ref, no plaintext copy — a genuine redundant authority, either of
    which alone suffices. Used only by the disjunctive scope-boundary fixture.
    """
    slot = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://agentgraph.co/ns/trust-evidence/v1",
        ],
        "type": "TrustAttestation",
        "version": "0.3.2",
        "claim_type": "authority",
        "issuer": "did:web:issuer-c.example",
        "subject": {"did": SUBJECT},
        "evidence_basis": {
            "delegation_chain": [
                {
                    "hop": 0,
                    "delegator_did": "did:aps:z6MkHumanPrincipalIndependenceDemoTwo",
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
    return sign_slot(slot, priv_c, KID_C)


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


def build_envelopes() -> dict:
    """Build every fixture in memory and return {filename: envelope-dict}."""
    priv_a = Ed25519PrivateKey.from_private_bytes(SEED_A)
    priv_b = Ed25519PrivateKey.from_private_bytes(SEED_B)
    priv_c = Ed25519PrivateKey.from_private_bytes(SEED_C)

    signed_a = slot_a(priv_a)
    # recomputable-evidence.independence:v1 binding hash of A's proof-stripped preimage.
    authority_ref = binding_hash(signed_a)

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

    # ---- OR-composition scope boundary (DISJUNCTIVE — documented FAIL) --------
    # Echo-Merlini's scope finding, promoted to a fixture. Two SAME-TYPE authority
    # slots (issuer A and issuer C), either of which alone suffices — a legitimate
    # disjunctive OR-composition. R3 as written quantifies over EACH single gating
    # slot ("drop X ⇒ composite MUST deny"), which is correct only for conjunctive
    # compositions. Applied to an honest OR, the single-slot quantification MISFIRES:
    # drop either authority and the other still permits, so R3 reports legitimate
    # redundancy as laundering and the honest OR-composition FAILs. This is the
    # documented scope boundary, NOT a defect — the corrected quantification (R3 over
    # minimal sufficient sets) PASSes it, and verify.py computes both.
    signed_c = slot_authority_c(priv_c)
    or_boundary = {
        "composition_version": "composed-v1",
        "independence_profile": "ctef-independence-v0",
        "subject_did": SUBJECT,
        "issued_at": "2026-08-01T00:10:00.000Z",
        "slots": {
            # Two slots of claim_type "authority" — only representable once the
            # format is lifted to permit same-type slots (keyed here by role name,
            # not by claim_type).
            "authority_x": signed_a,
            "authority_y": signed_c,
        },
        "jwks": {
            KID_A: _jwk(priv_a, KID_A),
            KID_C: _jwk(priv_c, KID_C),
        },
        "expected_composite": {
            "decision": "permit",
            "gating_slots": ["authority_x", "authority_y"],
            # Disjunctive: the composite permits iff ANY sufficient set fully
            # verifies. Either authority alone is sufficient.
            "composite_semantics": "disjunctive",
            "sufficient_sets": [["authority_x"], ["authority_y"]],
            "reasoning": (
                "Two independent authorities grant the same scope to the same "
                "subject; either alone suffices (honest redundancy / OR-composition)."
            ),
        },
        "expected_independence": {
            "profile": "ctef-independence-v0",
            "scope_boundary": True,
            "rubric_verdict": "FAIL",
            "why_fail_is_expected": (
                "R3's single-slot quantification (drop EACH gating slot ⇒ composite "
                "MUST deny) assumes a conjunctive composition. On this honest OR, "
                "dropping authority_x still permits via authority_y (and vice versa), "
                "so R3-single-slot does not flip and reports laundering. That is the "
                "scope boundary rubric §2 now states, demonstrated concretely — not a "
                "defect in this envelope."
            ),
            "corrected_quantification": (
                "R3 restated over minimal sufficient sets PASSes: within each minimal "
                "sufficient set every member is load-bearing FOR THAT SET, so no "
                "authority is laundered. verify.py computes "
                "r3_over_minimal_sufficient_sets and reports PASS."
            ),
        },
    }

    # ---- cross-suite binding artifact (CTEF side of a two-suite composition) --
    # Task C / the cross-fixture promised to Pablo. Demonstrates that the binding
    # hash is recomputable independently of the signature suite: a co-suite leg
    # (e.g. BIP340/Schnorr) content-addresses this CTEF authority by the SAME
    # recomputable-evidence.independence:v1 domain-separated binding hash, recomputed from the CTEF
    # preimage alone. We ship the CTEF side complete; the co-suite leg is a stub
    # naming exactly what the other suite must sign.
    cross_suite = {
        "artifact": "cross-suite-binding",
        "independence_profile": "ctef-independence-v0",
        "subject_did": SUBJECT,
        "purpose": (
            "Show CTEF's binding is recomputable across suites: the co-suite leg "
            "binds to this Ed25519 authority by a hash it recomputes from the CTEF "
            "preimage, without verifying CTEF's signature — independence spans suites."
        ),
        "ctef_authority": signed_a,
        "jwks": {KID_A: _jwk(priv_a, KID_A)},
        "authority_binding_hash": authority_ref,
        "binding_construction": (
            "sha256( b'recomputable-evidence.independence:v1:' + RFC8785-JCS(proof-stripped "
            "ctef_authority) ), lowercase hex, 'sha256:'-prefixed."
        ),
        "co_suite_leg": {
            "status": "NEEDED_FROM_CO_SUITE",
            "suite": (
                "BIP340/Schnorr (secp256k1), e.g. a trustless-ai/cross-reference-"
                "console cell, OR any suite verifiable against a published key"
            ),
            "must_embed": {
                "evidence_basis.authority_ref": authority_ref,
            },
            "requirement": (
                "The co-suite leg MUST embed the authority_ref above VERBATIM inside "
                "its OWN signed preimage, and be signed under its own suite. A verifier "
                "recomputes this binding hash from ctef_authority's JCS preimage alone "
                "(no Ed25519 verification needed) and requires it to equal the co-suite "
                "leg's embedded authority_ref, with the CTEF authority present and "
                "independently verified."
            ),
            "independence_property": (
                "Drop the CTEF authority and the co-suite leg's authority_ref no longer "
                "resolves to a present, verified slot — the composite denies. The "
                "binding is content-addressed and suite-independent: neither leg "
                "verifies the other's signature; both recompute the shared hash from "
                "public bytes."
            ),
        },
    }

    return {
        "valid-composition.json": valid,
        "laundered-authority.json": laundered,
        "copy-with-binding.json": copy_bound,
        "or-composition-scope-boundary.json": or_boundary,
        "cross-suite-binding.json": cross_suite,
    }


def build() -> None:
    FIX.mkdir(exist_ok=True)
    envelopes = build_envelopes()
    for fn, env in envelopes.items():
        (FIX / fn).write_text(json.dumps(env, indent=2) + "\n")
        print(f"wrote {fn}")
    print("authority_ref (recomputable-evidence.independence:v1 domain-separated binding hash of A):",
          envelopes["valid-composition.json"]["slots"]["continuity"]
          ["evidence_basis"]["authority_ref"])


def check() -> int:
    """Regenerate every fixture in memory and diff against the committed bytes.

    Exit 0 iff every on-disk fixture is byte-identical to a fresh regeneration —
    the reproducibility property (regenerate-and-diff, not trust-the-bytes)."""
    envelopes = build_envelopes()
    drift = []
    for fn, env in envelopes.items():
        want = json.dumps(env, indent=2) + "\n"
        path = FIX / fn
        have = path.read_text() if path.exists() else None
        status = "ok" if have == want else ("MISSING" if have is None else "DRIFT")
        print(f"  {fn}: {status}")
        if status != "ok":
            drift.append(fn)
    if drift:
        print(f"\nCHECK FAILED — {len(drift)} fixture(s) do not reproduce: {drift}")
        return 1
    print("\nALL FIXTURES REPRODUCE BYTE-FOR-BYTE FROM FIXED SEEDS")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="regenerate in memory and diff against committed fixtures "
                         "(exit nonzero on drift); do not write")
    args = ap.parse_args()
    if args.check:
        sys.exit(check())
    build()
