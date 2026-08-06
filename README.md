# composed-attestation-3leg-worked-example

**DRAFT — not published, not anchored. Internal review before responding in
ERCs t/28083.**

A worked example composing three independently verifiable references, each
covering a different vantage on the same `artifact_hash`
(`bdb4d93c…fbdb3`), following the pattern proposed in ERC-8274
(EthMagicians t/28083):

| Leg | What | Produced by | Verified here |
|-----|------|-------------|----------------|
| 1 — transparent | WYRIWE, live Sepolia contract `0x3f98686f2D286A95435BA5916ec663219BE387Ad` | TMerlini | No — referenced only, out of scope for this script |
| 2 — ours | `action_ref` (action-ref-v1) + `decision_binding_ref` (decision-binding-ref-v1.0), same specs/fixtures as every other worked example in argentum-core | us | Yes — recomputed from declared preimage |
| 3 — attested | `decision_ref` = `sha256:5bca0bf…b9b9`, invinoveritas ledger entry [#236](https://api.babyblueviper.com/ledger/236) | babyblueviper1 | Yes — recomputed from declared preimage, cross-checked against a live re-fetch |

## Doctrine: recompute, don't trust a summary

Same pattern as CTEF/CONSILIUM: nobody's prose description of what a hash
covers is taken at face value. Leg 3's `decision_ref` was recomputed
independently here from the raw verdict object at the source URL — byte-exact
match confirmed before this repo used it for anything. Leg 1 is explicitly
**not** verified by this repo (flagged `SKIP` by the verifier) — it wasn't
produced by us and babyblueviper1's own framing treats it as separately
checkable.

## What's here

| Path | What it is |
|------|-----------|
| `scripts/produce.py` | Builds `artifacts/manifest.json`: leg 3 copied verbatim + recomputed, leg 2 derived per our specs against a synthetic demo action bound to the shared `artifact_hash`, leg 1 referenced only. |
| `verifier/verify.py` | Independent (stdlib-only) verifier. Recomputes leg 3 from the cached preimage AND from a live re-fetch of the ledger entry; recomputes leg 2's `action_ref`/`decision_binding_ref`; explicitly skips leg 1. |
| `artifacts/manifest.json` | The canonical instance. |

## Reproduce

```bash
python3 scripts/produce.py artifacts
python3 verifier/verify.py
```

## Open, before this goes anywhere public

- Leg 2 today uses a synthetic demo action (`composed-attestation.review`)
  bound to entry #236's `artifact_hash`, reusing the existing verdict per
  babyblueviper1's own offer ("no hace falta reusar el #236"). A purpose-built
  fresh verdict against an `artifact_hash` we mint ourselves is the other
  option they offered — not requested yet.
- Not anchored on-chain. If this composition gets a green light, leg 2's
  `action_ref` anchors into `AnchorRegistry`
  (`0x49fEcA52bC634a9Ab773226D16619deC547794aa`) same as every other worked
  example — no new infra needed.
- No outreach to TMerlini for leg 1 — referenced from babyblueviper1's own
  post, not confirmed independently by us.

## Licenses

This repo is Apache-2.0 (same as argentum-core, whose specs/fixtures leg 2
reuses).
