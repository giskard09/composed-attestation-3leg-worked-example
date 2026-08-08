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
  * or-composition-scope-boundary.json ⇒ honest DISJUNCTIVE (OR) composition; the
                                rubric's single-slot R3 quantification MISFIRES and
                                reports FAIL. Documented scope boundary, not a defect:
                                R3 restated over minimal sufficient sets PASSes it.

It also runs a cross-suite check (Task C): it recomputes the CTEF authority's
action-ref v2 binding hash from its own preimage, showing the binding a co-suite
leg would content-address is recomputable independently of the signature suite.

`authority_ref` is the action-ref v2 domain-separated binding hash
(``mycelium.action-ref:v2:`` prepended to the JCS preimage before SHA-256); the
signature digest stays raw JCS.

Exit code 0 iff every fixture's computed rubric verdict matches its declared
``expected_independence.rubric_verdict`` (i.e. the rubric behaved as specified,
INCLUDING correctly failing the negative fixture AND the documented OR boundary).

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

# action-ref v2 domain-separation tag for the `authority_ref` binding hash
# (argentum, tagged/live at commit 96931c9). Applied to the content-address only;
# the signature digest below stays raw JCS (matches this repo's CTEF substrate).
ACTION_REF_V2_TAG = b"mycelium.action-ref:v2:"


# --- crypto helpers (mirror generate_fixtures.py / envelope_v2.py) ------------

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(payload: dict) -> bytes:
    stripped = {k: v for k, v in payload.items() if k != "proof"}
    return rfc8785.dumps(stripped)


def payload_hash(payload: dict) -> str:
    """Raw SHA-256 of the JCS preimage — the SIGNATURE digest (no domain tag)."""
    return "sha256:" + hashlib.sha256(canonical(payload)).hexdigest()


def binding_hash(payload: dict) -> str:
    """action-ref v2 domain-separated content address used for `authority_ref`:
    SHA-256( ACTION_REF_V2_TAG + JCS(proof-stripped payload) ). Distinct from the
    signature digest so the tag scopes the binding without changing how slots sign."""
    return "sha256:" + hashlib.sha256(ACTION_REF_V2_TAG + canonical(payload)).hexdigest()


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
    """binding hashes (action-ref v2 domain-separated) of present, verified slots —
    the value space `authority_ref` resolves against."""
    jwks = env.get("jwks", {})
    return {
        binding_hash(s) for s in env["slots"].values()
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
        binding_hash(v) for v in slots.values() if verify_slot_signature(v, jwks)
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


# --- disjunctive (OR) composite + the scope-boundary quantifications ----------
# These support the or-composition-scope-boundary.json fixture (Echo-Merlini's
# scope finding). The rubric's R3 text quantifies over EACH single gating slot,
# which is correct for conjunctive compositions only. On a disjunctive (OR)
# composition the honest composite permits iff ANY declared sufficient set fully
# verifies — and then the single-slot quantification misfires. We compute BOTH the
# single-slot R3 (which FAILs the honest OR — the documented boundary) and the
# corrected R3-over-minimal-sufficient-sets (which PASSes it).

def _slot_load_bearing(slot: dict, verified_hashes: set, jwks: dict) -> bool:
    if not verify_slot_signature(slot, jwks):
        return False
    ref = slot.get("evidence_basis", {}).get("authority_ref")
    if ref is not None and ref not in verified_hashes:
        return False
    return True


def _set_satisfied(names, slots: dict, jwks: dict) -> bool:
    """A slot-set is 'sufficient' iff it is non-empty and every named slot is
    present and load-bearing (verifies + its authority_ref, if any, resolves)."""
    if not names:
        return False
    verified_hashes = {
        binding_hash(v) for v in slots.values() if verify_slot_signature(v, jwks)
    }
    return all(
        n in slots and _slot_load_bearing(slots[n], verified_hashes, jwks)
        for n in names
    )


def disjunctive_decision(env: dict, drop: Optional[str] = None) -> str:
    """Honest OR composite: permit iff SOME declared sufficient set fully verifies."""
    slots = {k: v for k, v in env["slots"].items() if k != drop}
    jwks = env.get("jwks", {})
    for suff in env["expected_composite"]["sufficient_sets"]:
        if _set_satisfied(suff, slots, jwks):
            return "permit"
    return "deny"


def r3_over_minimal_sufficient_sets(env: dict) -> bool:
    """The corrected R3 for disjunctive compositions: independence is checked WITHIN
    each minimal sufficient set, not across the disjunction. A set launders iff some
    member can be dropped and the set stays sufficient (that member was not
    load-bearing for its set). An honest OR of singleton authorities passes: dropping
    the sole member of a singleton set leaves the empty set, which is not sufficient."""
    slots = env["slots"]
    jwks = env.get("jwks", {})
    for suff in env["expected_composite"]["sufficient_sets"]:
        for member in suff:
            reduced = [x for x in suff if x != member]
            if _set_satisfied(reduced, slots, jwks):
                return False  # member not load-bearing within its set -> within-set launder
    return True


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
    # A disjunctive (OR) composition declares sufficient_sets; the honest composite
    # is the OR rule. Otherwise the conjunctive honest composite applies.
    disjunctive = "sufficient_sets" in env["expected_composite"]
    decide = disjunctive_decision if disjunctive else composite_decision
    # R3: independence via the rubric's single-slot quantification — drop EACH
    # gating slot and require the honest composite to flip to deny.
    drop_flips = {}
    for name in env["expected_composite"]["gating_slots"]:
        drop_flips[name] = decide(env, drop=name)
    independence_holds = all(v == "deny" for v in drop_flips.values())
    launder = laundering_detected(env)
    checks["R3_drop_one_signature_fails"] = independence_holds and not launder
    verdict = "PASS" if all(checks.values()) else "FAIL"
    extra = {}
    if disjunctive:
        # The scope boundary: the single-slot R3 above misfires on an honest OR;
        # the corrected quantification (over minimal sufficient sets) does not.
        extra["disjunctive"] = True
        extra["r3_over_minimal_sufficient_sets"] = (
            "PASS" if r3_over_minimal_sufficient_sets(env) else "FAIL"
        )
    return verdict, checks, drop_flips, launder, extra


def cross_suite_check() -> bool:
    """Task C: recompute the CTEF authority's binding hash from its own preimage and
    confirm it matches the artifact's declared value — the CTEF side of a two-suite
    composition, verifiable without any co-suite artifacts. Returns True on match."""
    fn = "cross-suite-binding.json"
    path = FIX / fn
    if not path.exists():
        return True  # optional artifact; nothing to check
    art = json.loads(path.read_text())
    authority = art["ctef_authority"]
    jwks_kid = authority["proof"]["verificationMethod"]
    # The co-suite leg needs only the recomputed binding hash — NOT CTEF's signature.
    recomputed = binding_hash(authority)
    declared = art["authority_binding_hash"]
    match = recomputed == declared
    # Independently confirm the CTEF authority itself verifies (R1) for completeness.
    sig_ok = verify_slot_signature(authority, {jwks_kid: _jwk_of(art, jwks_kid)})
    print(f"\n=== {fn} (cross-suite, Task C) ===")
    print(f"  recomputed authority binding hash matches declared: "
          f"{'ok' if match else 'MISMATCH'}")
    print(f"  CTEF authority signature verifies independently (R1): "
          f"{'ok' if sig_ok else 'FAIL'}")
    print(f"  co-suite leg: {art['co_suite_leg']['status']} "
          f"(must embed authority_ref = {declared})")
    return match and sig_ok


def _jwk_of(artifact: dict, kid: str) -> dict:
    """Locate the JWK for kid inside the cross-suite artifact's embedded authority."""
    # The cross-suite artifact ships the authority leg; its key rides in the parent
    # fixtures' jwks. Recompute from the authority's own public material is not
    # possible, so we accept the leg's kid and pull the matching jwk if present.
    for src in (artifact.get("jwks", {}),):
        if kid in src:
            return src[kid]
    return {}


def main() -> int:
    files = [
        "valid-composition.json",
        "laundered-authority.json",
        "copy-with-binding.json",
        "or-composition-scope-boundary.json",
    ]
    all_ok = True
    for fn in files:
        env = json.loads((FIX / fn).read_text())
        verdict, checks, drop_flips, launder, extra = rubric_verdict(env)
        expected = env["expected_independence"]["rubric_verdict"]
        ok = verdict == expected
        all_ok = all_ok and ok
        boundary = env["expected_independence"].get("scope_boundary")
        label = "  [SCOPE BOUNDARY — documented FAIL, not a defect]" if boundary else ""
        print(f"\n=== {fn} ==={label}")
        for k, v in checks.items():
            print(f"  {k}: {'ok' if v else 'FAIL'}")
        print(f"  honest composite drop-experiment: {drop_flips}")
        print(f"  laundering_detected: {launder}")
        if extra.get("disjunctive"):
            print(f"  R3 single-slot quantification (rubric text): "
                  f"{'holds' if checks['R3_drop_one_signature_fails'] else 'MISFIRES on honest OR'}")
            print(f"  R3 over minimal sufficient sets (corrected): "
                  f"{extra['r3_over_minimal_sufficient_sets']}")
        print(f"  rubric verdict: {verdict}  (expected {expected})  "
              f"-> {'OK' if ok else 'MISMATCH'}")
    cross_ok = cross_suite_check()
    all_ok = all_ok and cross_ok
    print("\n" + ("ALL FIXTURES BEHAVED AS SPECIFIED" if all_ok
                   else "RUBRIC DID NOT BEHAVE AS SPECIFIED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
