#!/usr/bin/env python3
"""Independent verifier for the CTEF independence / neutrality rubric.

Issuer-neutral and dependency-light: uses only ``rfc8785`` (RFC 8785 JCS) and
``cryptography`` (Ed25519) — no AgentGraph scanner, no APS SDK, no AgentID SDK.
A third-party reviewer can run this against any composed envelope that declares
``independence_profile: ctef-independence-v0``.

It applies the five rubric requirements (see rubric.md) and, crucially, runs the
DROP-ONE-SIGNATURE experiment (R3) that separates a genuine composition from an
authority-laundering one:

  * valid-composition.json    ⇒ drop A ⇒ composite DENY  ⇒ rubric PASS
  * laundered-authority.json  ⇒ drop A ⇒ composite PERMIT ⇒ rubric FAIL (caught)
  * copy-with-binding.json    ⇒ plaintext copy + resolving authority_ref ⇒ PASS
                                (R4 pragmatic middle: copy permitted iff bound)

Exit code 0 iff every fixture's computed rubric verdict matches its declared
``expected_independence.rubric_verdict`` (i.e. the rubric behaved as specified,
INCLUDING correctly failing the negative fixture).

Run:  python3 verify.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Optional

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIX = Path(__file__).parent  # composed/v1/ — fixtures sit alongside this script


# --- crypto helpers (mirror generate_fixtures.py / envelope_v2.py) ------------

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(payload: dict) -> bytes:
    stripped = {k: v for k, v in payload.items() if k != "proof"}
    return rfc8785.dumps(stripped)


def payload_hash(payload: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(payload)).hexdigest()


def pubkey_from_jwk(jwk: dict) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))


def verify_slot_signature(slot: dict, jwks: dict) -> bool:
    """R1: recompute the slot's own JCS preimage and verify its detached JWS."""
    proof = slot.get("proof")
    if not proof or proof.get("type") != "Ed25519Signature2020":
        return False
    vm = proof.get("verificationMethod")
    jwk = jwks.get(vm)
    if not jwk:
        return False
    parts = proof.get("jws", "").split(".")
    if len(parts) != 3:
        return False
    sig = _b64url_decode(parts[2])
    digest = bytes.fromhex(payload_hash(slot).split(":", 1)[1])
    try:
        pubkey_from_jwk(jwk).verify(sig, digest)
        return True
    except (InvalidSignature, ValueError):
        return False


# --- rubric requirements ------------------------------------------------------

def r1_each_slot_verifies(env: dict) -> bool:
    jwks = env.get("jwks", {})
    return all(verify_slot_signature(s, jwks) for s in env["slots"].values())


def r2_subject_binding(env: dict) -> bool:
    subj = env["subject_did"]
    for slot in env["slots"].values():
        s = slot.get("subject", {})
        did = s.get("did") if isinstance(s, dict) else None
        if did != subj:
            return False
    return True


# Fields that carry a *plaintext copy* of another leg's grant (self-asserted
# authority). Under R4 these are permitted ONLY alongside a resolving authority_ref.
GRANT_COPY_FIELDS = ("granted_scope",)


def _present_verified_hashes(env: dict) -> set:
    jwks = env.get("jwks", {})
    return {
        payload_hash(s) for s in env["slots"].values()
        if verify_slot_signature(s, jwks)
    }


def r4_no_bare_selfassert(env: dict) -> bool:
    """R4 (pragmatic middle): a leg MAY inline a plaintext copy of another leg's
    grant ONLY IF it ALSO carries an ``authority_ref`` that resolves to a present,
    verified slot. A *bare* plaintext copy — a grant-copy field with no resolving
    ``authority_ref`` — FAILS: it is self-attestation standing in for the
    referenced issuer's signature."""
    present_hashes = _present_verified_hashes(env)
    for slot in env["slots"].values():
        eb = slot.get("evidence_basis", {})
        if not any(f in eb for f in GRANT_COPY_FIELDS):
            continue
        ref = eb.get("authority_ref")
        if ref is None or ref not in present_hashes:
            return False  # bare self-asserted copy — no binding hash to a real leg
    return True


def r5_content_addressing(env: dict) -> bool:
    """R5: any authority_ref MUST resolve to the JCS hash of a present, verified slot."""
    present_hashes = _present_verified_hashes(env)
    for slot in env["slots"].values():
        ref = slot.get("evidence_basis", {}).get("authority_ref")
        if ref is not None and ref not in present_hashes:
            return False
    return True


def composite_decision(env: dict, drop: Optional[str] = None) -> str:
    """The independence-correct composite rule.

    permit iff EVERY gating slot independently:
      - has a verifying signature, AND
      - has every content-addressed dependency (authority_ref) satisfied by a
        present + verified slot.

    A slot that only self-asserts a copy of another slot's grant (no
    authority_ref) contributes NOTHING toward that other slot's authority — so a
    conformant composite cannot be fooled by the laundered fixture. `drop` removes
    one slot to run the R3 experiment.
    """
    slots = {k: v for k, v in env["slots"].items() if k != drop}
    jwks = env.get("jwks", {})
    verified_hashes = {
        payload_hash(v) for v in slots.values() if verify_slot_signature(v, jwks)
    }
    gating = env["expected_composite"]["gating_slots"]
    for name in gating:
        slot = slots.get(name)
        if slot is None:
            return "deny"
        if not verify_slot_signature(slot, jwks):
            return "deny"
        ref = slot.get("evidence_basis", {}).get("authority_ref")
        if ref is not None and ref not in verified_hashes:
            return "deny"
    return "permit"


def laundering_detected(env: dict) -> bool:
    """R3 core: does an inlined self-asserted grant let a permissive composite
    survive the drop-A test? We model the permissive verifier a laundered
    composition relies on, and check whether removing each non-self-sufficient
    gating slot actually flips the decision."""
    # Laundering requires a *bare* self-asserted copy (an R4 violation). If every
    # inlined grant copy is backed by a resolving authority_ref, the envelope is
    # honestly bound under the pragmatic-middle R4 and there is nothing to launder.
    if r4_no_bare_selfassert(env):
        return False
    permissive = permissive_composite_decision(env)
    if permissive != "permit":
        return False
    # For each gating slot, drop it; if a permissive composite STILL permits, the
    # dropped slot's authority was laundered (not load-bearing).
    for name in env["expected_composite"]["gating_slots"]:
        if permissive_composite_decision(env, drop=name) == "permit":
            # Is the surviving permit legitimately independent, or laundered?
            # Legitimate: some OTHER present slot content-addresses the dropped
            # slot -> dropping should have denied. If it still permits, the
            # authority came from a self-asserted copy => laundering.
            if _permit_relies_on_selfassert(env, dropped=name):
                return True
    return False


def permissive_composite_decision(env: dict, drop: Optional[str] = None) -> str:
    """Models the LAX composite a laundered envelope is built to satisfy: it
    accepts either a content-addressed authority_ref OR an inlined granted_scope
    plaintext copy as 'authority present'. This is the buggy verifier the rubric
    exists to expose."""
    slots = {k: v for k, v in env["slots"].items() if k != drop}
    jwks = env.get("jwks", {})
    for name in env["expected_composite"]["gating_slots"]:
        slot = slots.get(name)
        if slot is None:
            # missing slot: lax verifier still trusts an inlined copy elsewhere
            if _scope_asserted_anywhere(slots):
                continue
            return "deny"
        if not verify_slot_signature(slot, jwks):
            return "deny"
    return "permit"


def _scope_asserted_anywhere(slots: dict) -> bool:
    return any(
        "granted_scope" in s.get("evidence_basis", {}) for s in slots.values()
    )


def _permit_relies_on_selfassert(env: dict, dropped: str) -> bool:
    remaining = {k: v for k, v in env["slots"].items() if k != dropped}
    return _scope_asserted_anywhere(remaining)


# --- driver -------------------------------------------------------------------

def rubric_verdict(env: dict) -> str:
    """Compute PASS/FAIL for a composition under ctef-independence-v0."""
    checks = {
        "R1_each_slot_verifies": r1_each_slot_verifies(env),
        "R2_subject_binding": r2_subject_binding(env),
        "R4_no_bare_selfassert": r4_no_bare_selfassert(env),
        "R5_content_addressing": r5_content_addressing(env),
    }
    # R3: independence. Compute the honest composite with and without each leg.
    drop_flips = {}
    for name in env["expected_composite"]["gating_slots"]:
        drop_flips[name] = composite_decision(env, drop=name)
    independence_holds = all(v == "deny" for v in drop_flips.values())
    launder = laundering_detected(env)
    checks["R3_drop_one_signature_fails"] = independence_holds and not launder
    verdict = "PASS" if all(checks.values()) else "FAIL"
    return verdict, checks, drop_flips, launder


def main() -> int:
    files = [
        "valid-composition.json",
        "laundered-authority.json",
        "copy-with-binding.json",
    ]
    all_ok = True
    for fn in files:
        env = json.loads((FIX / fn).read_text())
        verdict, checks, drop_flips, launder = rubric_verdict(env)
        expected = env["expected_independence"]["rubric_verdict"]
        ok = verdict == expected
        all_ok = all_ok and ok
        print(f"\n=== {fn} ===")
        for k, v in checks.items():
            print(f"  {k}: {'ok' if v else 'FAIL'}")
        print(f"  honest composite drop-experiment: {drop_flips}")
        print(f"  laundering_detected: {launder}")
        print(f"  rubric verdict: {verdict}  (expected {expected})  "
              f"-> {'OK' if ok else 'MISMATCH'}")
    print("\n" + ("ALL FIXTURES BEHAVED AS SPECIFIED" if all_ok
                   else "RUBRIC DID NOT BEHAVE AS SPECIFIED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
