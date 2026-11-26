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
| 1 — transparent | WYRIWE, live Sepolia contract `0x3f98686f2D286A95435BA5916ec663219BE387Ad` | TMerlini | Four checks only, run by `verifier/verify.py` (see below); not produced by `scripts/produce.py` |
| 2 — ours | `action_ref` (action-ref-v1) + `decision_binding_ref` (decision-binding-ref-v1.0), same specs/fixtures as every other worked example in argentum-core | us | Yes — recomputed from declared preimage |
| 3 — attested | `decision_ref` = `sha256:5bca0bf…b9b9`, invinoveritas ledger entry [#236](https://api.babyblueviper.com/ledger/236) | babyblueviper1 | Yes — recomputed from declared preimage, cross-checked against a live re-fetch |

## Doctrine: recompute, don't trust a summary

Same pattern as CTEF/CONSILIUM: nobody's prose description of what a hash
covers is taken at face value. Leg 3's `decision_ref` was recomputed
independently here from the raw verdict object at the source URL — byte-exact
match confirmed before this repo used it for anything.

Leg 1 was not produced by us, and this repo makes no claim about its spec as
a whole. The verifier runs four checks on it: a local keccak recompute of the
calldata hash and of the PolicyAction preimage, a live `verify()` call on the
deployed Sepolia contract, and the same call with a tampered `outputHash`,
which must return false.

The `verified_by_us: false` field of `leg1_transparent` in `artifacts/manifest.json` is written by `scripts/produce.py`, which captures and recomputes nothing for leg 1. It does not describe the four checks that `verifier/verify.py` runs.

## What's here

| Path | What it is |
|------|-----------|
| `scripts/produce.py` | Builds `artifacts/manifest.json`: leg 3 copied verbatim + recomputed, leg 2 derived per our specs against a synthetic demo action bound to the shared `artifact_hash`, leg 1 referenced only. |
| `verifier/verify.py` | Independent (stdlib-only) verifier. Recomputes leg 3 from the cached preimage AND from a live re-fetch of the ledger entry; recomputes leg 2's `action_ref`/`decision_binding_ref`; runs four checks on leg 1 (local keccak of its calldata and of its PolicyAction preimage, live `verify()` on the Sepolia contract, and the tampered-`outputHash` negative); a source it cannot reach is reported `INCONCLUSIVE`. |
| `artifacts/manifest.json` | The canonical instance. |

## Reproduce

```bash
python3 scripts/produce.py artifacts
# anchor.sh needs OWNER_PRIVATE_KEY in env, not committed:
BASE_RPC=https://mainnet.base.org bash scripts/anchor.sh
python3 verifier/verify.py
```

## Verifier output contract

Every check ends in exactly one status:

| Status | Meaning |
|--------|---------|
| `PASS` | The check ran and the recomputed or observed value matches. |
| `FAIL` | The check ran and the value does not match (including: the RPC answered and the `Anchored` event is not there; the leg 1 `eth_call` answered with no data, i.e. no contract code at the address; or `verify()` reverted on the bound input). |
| `INCONCLUSIVE` | The check could not run: the source was unreachable after bounded retries, answered with something that is not a usable JSON-RPC result, `--no-network` was given, or `anchor.json` is absent. It is neither a pass nor a refutation. |

The last lines are a count (`N PASS, M FAIL, K INCONCLUSIVE`) and the exit code:

| Exit | When |
|------|------|
| `0` | No `FAIL` and no `INCONCLUSIVE`. Prints `ALL CHECKS PASS`. |
| `1` | At least one `FAIL`. |
| `2` | No `FAIL`, at least one `INCONCLUSIVE`. Prints that this is not a pass. |

Network behaviour:

- Transient failures (HTTP 429, 5xx, timeouts, connection errors) are retried up to 3 attempts with doubling backoff. Other HTTP errors are not retried. When all attempts fail the check is `INCONCLUSIVE`.
- The leg 2 on-chain check uses the RPC in the `BASE_RPC` environment variable when set, otherwise the `rpc` field of `artifacts/anchor.json`. The output line names which one was used. The leg 1 check uses `SEPOLIA_RPC` the same way.
- Each log returned by the RPC is re-checked in the verifier (registry address, `Anchored` topic, the ref, not removed) instead of trusting the RPC's own filtering. This does not make the RPC trusted: an RPC that forges a matching log would still be believed. Use an RPC you trust, or compare two.
- An answer the RPC gave is classified as an answer, not as could-not-query. For leg 1, empty `eth_call` data is `FAIL`, a revert on the bound input is `FAIL`, and a revert on the tampered `outputHash` is a `PASS` for the fail-closed check (the tampered output is rejected). Other JSON-RPC errors (rate limits and the like) stay `INCONCLUSIVE`.
- `--no-network` makes no network call at all. Every check that needs the network is reported `INCONCLUSIVE`, so an offline run exits 2.

Behaviour changes versus the earlier verifier: an unreachable leg 2 RPC used to end in a Python traceback; an unreachable leg 1 or leg 3 source was `FAIL` (leg 1) or a `[SKIP]` that still printed `ALL CHECKS PASS` (leg 3); both are now `INCONCLUSIVE` with exit 2.

Tests, with a local fake in place of the network:

```bash
python3 -I tests/test_verify_network.py
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
- Leg 1 (WYRIWE) is not anchored or produced by this repo; the verifier only runs the four checks described above.

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
