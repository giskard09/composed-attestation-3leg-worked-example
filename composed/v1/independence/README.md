# `composed/v1/` — CTEF independence fixtures (`ctef-independence-v0`)

This directory mirrors the real composed-envelope layout used at
`haroldmalikfrimpong-ops/agentid-aps-interop` `composed/v1/`: a `composed/v1/` folder holding
composed envelopes plus a single stdlib-only `verify.py` a third party can run offline. It drops
cleanly into any repo that already uses that convention.

Each fixture is a composed-v1 envelope over one subject DID, carrying two **signed** CTEF slots
(`authority` from issuer A, `continuity` from issuer B). Signatures are real Ed25519 detached
compact JWS over JCS-canonical (RFC 8785) preimages, produced deterministically from fixed seeds
by `generate_fixtures.py`. Public keys travel in each envelope's `jwks` block so the fixtures are
self-contained and offline-verifiable. Slots declare CTEF `version: "0.3.2"` (the normative
reference; see `../../rubric.md`).

Recompute everything:

```
python3 generate_fixtures.py && python3 verify.py
```

Exit code 0 prints `ALL FIXTURES BEHAVED AS SPECIFIED` iff every fixture's computed verdict
matches its declared `expected_independence.rubric_verdict`.

## Files

| File | Verdict | What it shows |
|---|---|---|
| `valid-composition.json` | **PASS** | B is content-addressed-bound to A via `authority_ref`; no plaintext copy. |
| `copy-with-binding.json` | **PASS** | B carries a plaintext `granted_scope` copy **and** a resolving `authority_ref`. The R4 permitted case (decision 5). |
| `laundered-authority.json` | **FAIL** | B inlines a **bare** plaintext copy of A's grant with **no** `authority_ref`. Laundering. The rubric must catch it. |
| `or-composition-scope-boundary.json` | **FAIL** (documented) | An honest **disjunctive** OR-composition (two same-type authorities, either sufficient) that the rubric's single-slot R3 quantification misfires on. The **documented scope boundary** (rubric §2), not a defect: `verify.py`'s corrected `r3_over_minimal_sufficient_sets` PASSes it. |
| `cross-suite-binding.json` | n/a (artifact) | The CTEF side of a two-suite composition (rubric §9). `verify.py` recomputes the authority's action-ref v2 binding hash from its own preimage; the co-suite leg is a stub naming what the other suite must sign. |

`authority_ref` uses argentum's **action-ref v2** domain-separation tag (`mycelium.action-ref:v2:`
prepended to the JCS preimage before SHA-256); the signature digest stays raw JCS. Run
`python3 generate_fixtures.py --check` to regenerate every fixture in memory and diff it against the
committed bytes (exit nonzero on any drift).

## `valid-composition.json` — independence HOLDS (rubric PASS)

Slot B is content-addressed-bound to slot A: `B.evidence_basis.authority_ref =
sha256(JCS(preimage_A))`, and that `authority_ref` is inside B's signed bytes.

- Both slots verify independently (R1), share the subject (R2), the `authority_ref` resolves to
  A's recomputed preimage hash (R5), and no leg carries a bare self-asserted copy (R4).
- **Drop-A experiment (R3):** remove A ⇒ B's `authority_ref` no longer resolves to a present,
  verified slot ⇒ honest composite returns `deny`. A is load-bearing. **Independence holds.**

## `copy-with-binding.json` — plaintext copy PERMITTED because bound (rubric PASS)

Identical to `valid-composition.json` except B's `evidence_basis` also carries a convenience
`granted_scope` plaintext copy **alongside** the resolving `authority_ref`. Under R4's pragmatic
middle this is permitted: the copy is decorative, a conformant verifier reads the binding hash,
never the copy. Drop A and the binding stops resolving ⇒ `deny`. Delete the `authority_ref` and
leave only the copy and this fixture becomes `laundered-authority.json`.

## `laundered-authority.json` — NEGATIVE: authority laundered (rubric FAIL)

Identical slot A. But slot B does **not** bind to A by hash — instead B inlines a **bare**
self-asserted plaintext copy of A's grant
(`evidence_basis.granted_scope: ["action:read","resource:documents"]`) with **no**
`authority_ref`. B signs its own copy. A permissive composite that reads that inlined scope treats
B's word as authoritative and permits while A is present.

- **Drop-A experiment (R3):** remove A ⇒ the inlined `granted_scope` copy is still there and still
  signed by B ⇒ a permissive composite **still permits**. A's signature was never load-bearing;
  A's authority was **laundered** into B.
- Requirements violated: **R4** (bare self-asserted copy) and **R3** (drop-one-signature did not
  fail).
- Verifier verdict: **FAIL** — and `verify.py` exits 0 because failing this fixture is the
  *correct, expected* behavior.

## `or-composition-scope-boundary.json` — the disjunctive scope boundary (documented FAIL)

Two authority slots (`authority_x` from issuer A, `authority_y` from issuer C) grant the same scope
to the same subject; **either alone suffices**. This is a legitimate OR-composition — honest
redundancy, not laundering. But the rubric's R3 quantifies over **each single gating slot** ("drop X
⇒ composite MUST deny"), which is correct only for **conjunctive** compositions. Applied here it
misfires: drop `authority_x` and the composite still permits via `authority_y` (and vice versa), so
R3-single-slot never flips and reports laundering. `verify.py` prints both the misfiring single-slot
result **and** the corrected `r3_over_minimal_sufficient_sets` (which PASSes), so the FAIL reads as a
scope demonstration. It exists so no one lifts the rubric to a disjunctive format without restating
R3 over minimal sufficient sets first (rubric §2).

## `cross-suite-binding.json` — independence across signature suites (rubric §9)

The CTEF `authority` leg plus its recomputed action-ref v2 `authority_binding_hash`. A co-suite leg
(e.g. BIP340/Schnorr) binds to it by embedding that hash **verbatim inside its own signed preimage**;
a verifier confirms the binding by recomputing the hash from the CTEF preimage alone, never verifying
CTEF's signature — so independence spans suites. `verify.py` runs the CTEF-side recomputation today;
the co-suite leg is named as `NEEDED_FROM_CO_SUITE`.

## Why the set is the whole point

`valid` and `laundered` are byte-identical except for how B references A: a **content-addressed
hash inside B's signature** (valid) vs. a **bare duplicated plaintext field B asserts about
itself** (laundered). `copy-with-binding` sits between them: it carries *both*, and passes,
proving the rule is precisely "copy is fine iff a resolving binding hash is also present."
`or-composition-scope-boundary` marks the edge of the rule's remit — where the conjunctive R3
stops applying. The drop-one-signature test surfaces every one of these mechanically — no reviewer
has to trust anyone's prose about what the composition "means."
