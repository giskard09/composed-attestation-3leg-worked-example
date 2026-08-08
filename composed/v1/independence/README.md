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

## Why the triple is the whole point

`valid` and `laundered` are byte-identical except for how B references A: a **content-addressed
hash inside B's signature** (valid) vs. a **bare duplicated plaintext field B asserts about
itself** (laundered). `copy-with-binding` sits between them: it carries *both*, and passes,
proving the rule is precisely "copy is fine iff a resolving binding hash is also present."
The drop-one-signature test surfaces the difference mechanically — no reviewer has to trust
anyone's prose about what the composition "means."
