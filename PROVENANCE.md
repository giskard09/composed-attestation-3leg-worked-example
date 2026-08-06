# Provenance

**Status: draft, unpublished, not anchored.**

## Leg 3 — babyblueviper1 / invinoveritas ledger #236

- Fetched live from `https://api.babyblueviper.com/ledger/236` (2026-08-06).
- `verdict` object copied verbatim into `scripts/produce.py` — no field
  added, removed, or altered.
- `decision_ref` (`sha256:5bca0bf044c8e1c8e16a01bf3ee44b12c305ce6a50dd9789ff73cbd13482b9b9`)
  recomputed independently from the 8 fields named in the verdict's own
  `decision_ref_preimage_fields` (absent fields present as JSON `null`, per
  their `decision_ref_preimage_rule`) — matches byte-exact.
- `artifact_hash` (`bdb4d93c421d54883a0c31821d37d197a91a972062be28babed3599dcf2fbdb3`)
  is the shared anchor point for all three legs in this worked example.
- We did not verify the Nostr signature (`sig` field) or the ledger's hash
  chain (`prev_head_hash`/`content_hash`/`head_hash`) — only the
  `decision_ref` derivation, which is what this worked example composes
  against.

## Leg 2 — ours

- `action_ref` per `action-ref-v1` (argentum-core,
  `docs/spec/action-ref.md`): 4-field preimage
  (`agent_id`/`action_type`/`scope`/`timestamp`), JCS (sort_keys, compact
  separators) + SHA-256. `agent_id: worked-example.composed-attestation-3leg`
  — synthetic identity for this example, not a production agent.
- `decision_binding_ref` per `decision-binding-ref-v1.0` (argentum-core,
  `docs/spec/decision-binding-ref-v1.0.md`): binds our `action_ref` to
  `decision_id: invinoveritas-ledger-236` and a `context_digest` over leg 3's
  preimage — the mechanical link between our leg and theirs, itself
  independently recomputable.
- `scope` and `timestamp` are synthetic demo values, chosen for this worked
  example. No claim of a real production trail.

## Leg 1 — WYRIWE / TMerlini

- Not produced, not verified, not touched by this repo. Referenced solely
  from babyblueviper1's own ledger submission note
  (`root_interactive_mcp`, entry #236): "transparent (TMerlini
  recompute/wyriwe, live Sepolia
  0x3f98686f2D286A95435BA5916ec663219BE387Ad, post #153)."
- No outreach to TMerlini has happened. No claim of their participation in,
  or endorsement of, this specific composed example.

## What this is not

- Not a claim that babyblueviper1, invinoveritas, or TMerlini endorse this
  composition — it applies our own specs to a real, independently
  recomputed third-party reference, nothing more.
- Not anchored on-chain yet. Not published. Not posted to ERCs t/28083.
