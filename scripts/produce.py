#!/usr/bin/env python3
"""
Composes a 3-leg attestation worked example (ERC-8274 thread, EthMagicians
t/28083) around a single artifact_hash:

  Leg 1 (confidential->transparent) — WYRIWE / TMerlini. NOT produced or
    verified by us. Referenced only: live contract on Sepolia
    0x3f98686f2D286A95435BA5916ec663219BE387Ad. Verify independently if/when
    needed — out of scope for this script.
  Leg 2 (ours) — action_ref / decision_binding_ref v1.0 (argentum-core specs,
    same fixtures A-D as always) over a demo action bound to the shared
    artifact_hash.
  Leg 3 (attested) — babyblueviper1 / invinoveritas ledger entry #236,
    decision_ref = sha256:5bca0bf...b9b9. Reused as-is (their own offer said
    reuse of #236 is fine; a purpose-built fresh verdict is optional, not
    requested yet — this script does not contact them).

PROVENANCE: leg 3's verdict object is copied verbatim from
https://api.babyblueviper.com/ledger/236 (fetched 2026-08-06) and recomputed
here byte-for-byte -- not mocked, not summarized. Leg 1 is referenced, not
verified, by this script. Leg 2 is our own spec, synthetic demo params.
"""
import hashlib
import json
import os
import sys

OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "artifacts"
os.makedirs(OUT_DIR, exist_ok=True)


def jcs(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


SHARED_ARTIFACT_HASH = "bdb4d93c421d54883a0c31821d37d197a91a972062be28babed3599dcf2fbdb3"

# --- Leg 3 — babyblueviper1 / invinoveritas ledger #236, verbatim ----------
LEG3_VERDICT = {
    "artifact_hash": SHARED_ARTIFACT_HASH,
    "artifact_type": "onchain_action",
    "confidence": 0.84,
    "conformance_suite": "https://github.com/babyblueviper1/preaction-governance-conformance",
    "decision_ref": "sha256:5bca0bf044c8e1c8e16a01bf3ee44b12c305ce6a50dd9789ff73cbd13482b9b9",
    "decision_ref_preimage_fields": [
        "artifact_hash", "artifact_type", "policy_version", "verdict",
        "source_class", "vantage_limitation", "related_decision_ref",
        "intended_audience",
    ],
    "decision_ref_preimage_rule": (
        "every name in decision_ref_preimage_fields is a key in the hashed "
        "preimage object, always -- absent fields (e.g. vantage_limitation "
        "when not applicable) are present as JSON null, never omitted from "
        "the object."
    ),
    "engine_generation": 1,
    "key_id": "6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7",
    "platform": "invinoveritas",
    "policy_version": "invinoveritas.review.v7",
    "schema": "invinoveritas.verdict_proof.v1",
    "source_class": "agent_reported",
    "verdict": "reject",
    "verified_at": 1785802284,
    "vantage_limitation": (
        "source_class=agent_reported: nothing external confirms this /review "
        "call happened, or could not be bypassed, before the action it "
        "governs. Recomputability makes this record internally consistent "
        "(an occurrence claim) — it is not an absence/completeness "
        "claim, which needs a vantage the acting agent doesn't control. "
        "Sufficient as standalone evidence for a reversible action; for an "
        "irreversible or privileged action, treat this proof as advisory "
        "input, not standalone authorization, until paired with an "
        "independent mediation-point integration."
    ),
}
LEG3_PREIMAGE = {k: LEG3_VERDICT.get(k) for k in LEG3_VERDICT["decision_ref_preimage_fields"]}
leg3_recomputed = "sha256:" + sha256_hex(jcs(LEG3_PREIMAGE))
assert leg3_recomputed == LEG3_VERDICT["decision_ref"], "leg3 decision_ref mismatch — do not proceed"

# --- Leg 2 — ours: action_ref (action-ref-v1) + decision_binding_ref v1.0 --
timestamp = "2026-08-06T00:00:00.000Z"
action_preimage = {
    "agent_id": "worked-example.composed-attestation-3leg",
    "action_type": "composed-attestation.review",
    "scope": f"mycelium:composed-demo:artifact:{SHARED_ARTIFACT_HASH}",
    "timestamp": timestamp,
}
# action_ref (action-ref-v1 canonical form): plain hex, no prefix — this is
# what gets anchored as bytes32. Confirmed against argentum-core's own
# reference implementation (plugins/agt_evidence_anchor/action_ref.py) and
# every other *-action-ref-anchor worked example (r0x, machinefi, etc.) —
# none of them prefix it. Only decision-binding-ref-v1.0 wraps it with a
# "sha256:" prefix when embedding it in ITS OWN preimage (spec example,
# decision-binding-ref-v1.0.md line 77).
action_ref = sha256_hex(jcs(action_preimage))

decision_binding_payload = {
    "action_ref": "sha256:" + action_ref,
    "decision_at_ms": 1785802284000,
    "decision_id": "invinoveritas-ledger-236",
    "context_digest": "sha256:" + sha256_hex(jcs(LEG3_PREIMAGE)),
}
decision_binding_ref = "sha256:" + sha256_hex(
    json.dumps(dict(sorted(decision_binding_payload.items())), separators=(",", ":"), ensure_ascii=False)
)

leg2 = {
    "spec_action_ref": "action-ref-v1 (argentum-core, docs/spec/action-ref.md)",
    "spec_decision_binding_ref": "decision-binding-ref-v1.0 (argentum-core, docs/spec/decision-binding-ref-v1.0.md)",
    "action_preimage": action_preimage,
    "action_ref": action_ref,
    "anchor_ref_bytes32": "0x" + action_ref,
    "decision_binding_payload": decision_binding_payload,
    "decision_binding_ref": decision_binding_ref,
}

# --- Leg 1 — WYRIWE/TMerlini, referenced only ------------------------------
leg1 = {
    "label": "WYRIWE (TMerlini) — confidential/transparent leg",
    "produced_by_us": False,
    "verified_by_us": False,
    "chain": "Sepolia (11155111)",
    "contract": "0x3f98686f2D286A95435BA5916ec663219BE387Ad",
    "note": (
        "Referenced only, per babyblueviper1's own framing (EthMagicians "
        "t/28083 post #153). Not captured or recomputed by this script — "
        "verify independently against the live contract if/when needed."
    ),
}

manifest = {
    "fixture_id": "composed-attestation-3leg-worked-example",
    "thread": "ethresear.ch / ethereum-magicians t/28083 (ERC-8274)",
    "shared_artifact_hash": SHARED_ARTIFACT_HASH,
    "leg1_transparent": leg1,
    "leg2_ours": leg2,
    "leg3_attested": {
        "source": "https://api.babyblueviper.com/ledger/236",
        "fetched_at_utc": "2026-08-06",
        "verdict": LEG3_VERDICT,
        "preimage": LEG3_PREIMAGE,
        "decision_ref": LEG3_VERDICT["decision_ref"],
        "recomputed_locally": leg3_recomputed,
        "match": leg3_recomputed == LEG3_VERDICT["decision_ref"],
    },
    "provenance": (
        "Worked example, unpublished draft. Leg 3 is real (invinoveritas "
        "ledger #236, verbatim, recomputed byte-exact). Leg 2 is our own "
        "spec applied to a synthetic demo action bound to the same "
        "artifact_hash -- not a real production trail. Leg 1 is referenced "
        "from babyblueviper1's own framing, not produced or verified here. "
        "No claim of endorsement or integration by babyblueviper1, "
        "invinoveritas, or TMerlini beyond what each party has stated "
        "publicly in EthMagicians t/28083."
    ),
}

with open(os.path.join(OUT_DIR, "manifest.json"), "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")

print("=== composed-attestation-3leg-worked-example : producer ===")
print(f"leg3 decision_ref recompute match : {manifest['leg3_attested']['match']}")
print(f"leg2 action_ref                   : {leg2['action_ref']}")
print(f"leg2 anchor_ref_bytes32            : {leg2['anchor_ref_bytes32']}")
print(f"leg2 decision_binding_ref         : {leg2['decision_binding_ref']}")
print(f"wrote {OUT_DIR}/manifest.json")
