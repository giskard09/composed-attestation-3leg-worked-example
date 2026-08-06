# composed-attestation-3leg-worked-example

Leg 2's `action_ref` is anchored on Base mainnet:
[`0x723b18539f186c1b6dd904d51f832f6d3d103c4daef2f8e29590ec8d10dda353`](https://basescan.org/tx/0x723b18539f186c1b6dd904d51f832f6d3d103c4daef2f8e29590ec8d10dda353)
(block 49623528, `AnchorRegistry` `0x49fEcA52bC634a9Ab773226D16619deC547794aa`).

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
# anchor.sh needs OWNER_PRIVATE_KEY in env, not committed:
BASE_RPC=https://mainnet.base.org bash scripts/anchor.sh
python3 verifier/verify.py
```

## The anchor

- **Registry:** `0x49fEcA52bC634a9Ab773226D16619deC547794aa` (same CREATE2
  address on Base 8453, Arbitrum One 42161, Ink 57073).
- **Function:** `anchor(bytes32 ref)` — permissionless, no owner/roles/funds.
- **Leg 2's `action_ref`:** `86f1690e20a214faa9c0755a3cba860592c07d68c9312fdd6bc464de4b2c7fb2`
- **Tx:** `0x723b18539f186c1b6dd904d51f832f6d3d103c4daef2f8e29590ec8d10dda353`, block 49623528, Base mainnet.
- Leg 3's `decision_ref` is not separately anchored here — it already lives
  on invinoveritas's own Nostr-backed ledger (entry #236), independently
  checkable there.
- Leg 1 (WYRIWE) is not touched by this repo at all.

## Scope, explicit

- Leg 2 uses a synthetic demo action (`composed-attestation.review`) bound
  to entry #236's `artifact_hash`, reusing the existing verdict per
  babyblueviper1's own offer ("that's a real decision_ref to slot in") —
  decided over requesting a purpose-built fresh verdict, which they also
  offered as an option.
- No outreach to TMerlini for leg 1 — referenced from babyblueviper1's own
  post, not confirmed independently by us. Do not read anything in this
  repo as vouching for leg 1's correctness.

## Licenses

This repo is Apache-2.0 (same as argentum-core, whose specs/fixtures leg 2
reuses).
