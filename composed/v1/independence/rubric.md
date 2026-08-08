# Independence / Neutrality Rubric for Composed Evidence — `ctef-independence-v0`

**Status:** first-pass draft for the LFDT recomputable-evidence lab. Not submitted.
**Author:** Kenne Ives (founding committer).
**Worked example:** CTEF — Composable Trust Evidence Format (Ed25519/JWS over RFC 8785 JCS,
content-addressed; substrate maintained at `agentgraph-co/agentgraph`).
**Normative CTEF reference:** **CTEF v0.3.2** (settled). v0.3.3 is additive, backward-compatible
and maintainer-approved, but is marked CTEF-scoped with cross-spec pieces still in flight, so this
rubric pins to the settled 0.3.2 as its normative reference.
**Companion artifacts (in `composed/v1/`):** `valid-composition.json`,
`laundered-authority.json`, `copy-with-binding.json`, `verify.py` (issuer-neutral verifier),
`generate_fixtures.py` (reproducible signer).

---

## 1. What this rubric is for

When two or more independently-issued attestations (from specs A, B, …) are *composed* into
one object a consumer acts on, the composition must not let one spec's signature **launder
authority** into another. Each spec must stand on its own preimage and its own signature; the
composite verdict must depend on **every gating leg independently**.

The failure this rubric exists to catch: a composition where spec A's signature makes the
composite pass for a claim that spec B never actually, independently signed — so an actor who
controls A can manufacture a composite "permit" without B's genuine sign-off. That is
**authority laundering**, and it defeats the whole point of composing independent signals.

This rubric is written as **testable requirements a fixture can FAIL**, not prose. A composed
envelope either exhibits the drop-one-signature property or it does not, and `verify.py`
decides it mechanically.

## 2. Scope and vocabulary

- **Composed envelope** — one object carrying ≥2 attestation **slots** over a shared
  `subject_did`, plus an `expected_composite` decision. Shape follows the `composed-v1`
  convention already used at `haroldmalikfrimpong-ops/agentid-aps-interop` `composed/v1/`.
- **Slot / leg** — one spec's signed attestation: a proof-stripped body plus a **detached
  signature verifiable against a published key**. The requirements below are stated over that
  abstraction, not over any one curve. In CTEF terms: a `TrustAttestation` envelope with a
  `claim_type` and an Ed25519 `proof` (detached compact JWS) — the worked-example instantiation;
  a BIP340/Schnorr or ECDSA `proof` verified against a published key satisfies the same clause.
- **Preimage** — a slot's proof-stripped body, canonicalized with **RFC 8785 (JCS)**. The
  bytes a signature is computed over, and the bytes a hash addresses.
- **Binding hash** — `sha256:` + lowercase-hex SHA-256 of a slot's JCS preimage. This is how
  one leg **content-addresses** another (`evidence_basis.authority_ref`). `authority_ref` is
  **content-addressed only**: it is the plain SHA-256 of the referenced slot's JCS preimage,
  computed with **no domain-separation prefix**. Whether the lab wants a domain-separation tag on
  this hash (an `action-ref`-style prefix) is an **open alignment item** — see §8; the rubric and
  `verify.py` deliberately do not hard-code one.
- **Gating slot** — a slot the composite decision depends on (`expected_composite.gating_slots`).
- **Composite passes** — every gating slot verifies AND every content-addressed dependency
  resolves to a present, independently-verified slot (see R5). Operationally: `permit`.

A composed envelope opts into this rubric by declaring
`"independence_profile": "ctef-independence-v0"`.

## 3. Requirements

Each requirement is a predicate over a composed envelope. A conformant composition satisfies
**all** of them; a fixture that violates any one MUST be reported `FAIL` by a conformant
verifier.

These requirements are stated over **a detached signature verifiable against a published key**
and are therefore **signature-suite-agnostic**: Ed25519/JWS, BIP340/Schnorr (secp256k1), and
ECDSA all qualify wherever the text below says "signature" or "verify." The CTEF worked-example
fixtures happen to use Ed25519; nothing in R1–R5 depends on that choice.

### R1 — Per-spec preimage recomputation (independent verification)
For every slot, a verifier MUST recompute the slot's canonical preimage **from the slot's own
bytes** (JCS RFC 8785 over the proof-stripped body) and verify the slot's signature against
the issuer key named in its `proof.verificationMethod`, resolved from the envelope's published
`jwks` (or the issuer's DID document). No slot's verification may consume another slot's bytes,
key, or verdict. **A slot that only verifies transitively (because a neighbor vouched for it)
fails R1.**

### R2 — Subject-binding integrity
Every slot's `subject.did` MUST equal the envelope-level `subject_did`, verbatim. A composition
whose slots disagree about the subject is not one object about one agent; it is unrelated
attestations glued together and MUST be rejected.

### R3 — Independence: drop-one-signature ⇒ composite MUST fail (the core property)
For **each** gating slot X, removing X's signature (equivalently, removing slot X) MUST flip
the composite from `permit` to `deny`. Formally, for the honest composite rule `C`:

> A composition is *independence-valid* **iff** for every gating slot X: `C(envelope − X) = deny`.

If there exists a gating slot X such that the composite still returns `permit` with X removed,
then X's signature was **not load-bearing** — its authority was laundered into another leg —
and the composition MUST be reported `FAIL`. This is the operational meaning of
*"a composition passes ONLY IF removing spec A's signature makes validation under spec B FAIL."*

`verify.py` proves R3 by re-running the composite once per gating slot with that slot dropped,
and additionally models a **permissive** composite to detect the laundering pattern where an
inlined self-asserted copy of another leg's grant would survive the drop (see R4/R5).

### R4 — No *bare* self-asserted authority (plaintext copy permitted only when bound)
A leg MAY carry a plaintext copy of another leg's grant (e.g.
`evidence_basis.granted_scope: [...]`) as convenience data **only if** that same leg also carries
a content-addressed `authority_ref` (R5) that resolves to a present, independently-verified slot.
A **bare** plaintext copy — a grant-copy field with no such binding `authority_ref` — MUST be
reported `FAIL`: a copy is the issuer's own word, not the referenced issuer's signature, so on
its own it launders authority by construction. Where a copy sits alongside a resolving
`authority_ref`, the copy is **decorative**: a conformant verifier reads the binding hash, never
the copy, so the copy cannot become load-bearing. The cross-leg *dependency* is always carried by
the binding hash (R5), never by the duplicated field.

> **Strictness note (the pragmatic middle).** An earlier draft forbade the plaintext copy
> outright. This rubric relaxes that to: **copy-with-binding PASSES, bare-copy FAILS.** The strict
> drop-one-signature test (R3) remains the core invariant and is unaffected. `copy-with-binding.json`
> is the worked example of the permitted case; `laundered-authority.json` is the forbidden bare-copy
> case. The residual risk this permits — a *non-conformant* verifier that reads the plaintext copy
> and ignores the `authority_ref` — is a verifier-implementation defect, out of scope for an
> envelope-construction rubric; §4 pins the conformant rule that never reads the copy.

### R5 — Content-addressing / binding integrity
Where leg B depends on leg A, B's **signed** preimage MUST embed
`evidence_basis.authority_ref = <binding hash of A's preimage>`. A conformant verifier MUST:
1. recompute A's binding hash from A's own preimage, and
2. require that value to equal the `authority_ref` embedded in B's signed bytes, and
3. require A to be present and independently verified (R1).

Because `authority_ref` is inside B's signed preimage, B is cryptographically pinned to A's
*exact* authorization; and because A must be independently verified, B cannot inherit authority
from an absent or unverified A. Removing A therefore necessarily fails B's dependency — which
is exactly what makes R3 hold. Any `authority_ref` that does not resolve to a present, verified
slot MUST cause `FAIL` (fail-closed).

## 4. The honest composite rule (operational definition of "passes")

```
C(envelope) = permit  iff  for every gating slot X:
                 verify_signature(X) is true                       # R1
             AND (X has no authority_ref
                  OR authority_ref(X) ∈ { hash(Y) : Y present ∧ verify_signature(Y) })  # R5
           else deny
```

- No gating slot's verdict is derived from another slot's verdict.
- A self-asserted `granted_scope` copy contributes **nothing** toward any other slot's
  authority: the honest rule never reads it, so it cannot make the composite permit. A *bare*
  copy (no resolving `authority_ref`) additionally fails R4; a copy alongside a resolving
  `authority_ref` is permitted but still ignored here — only the binding hash is load-bearing.
- `verify.py` implements `C` and also a deliberately-lax `C_permissive` that *does* accept an
  inlined copy — used only to demonstrate that the laundered fixture would fool a permissive
  verifier, which is precisely the risk this rubric flags.

## 5. Conformance procedure

A fixture is conformant under `ctef-independence-v0` iff:
1. R1, R2, R4, R5 all hold, and
2. R3 holds: `C(envelope − X) = deny` for every gating slot X, and no laundering pattern is
   detectable.

`verify.py` prints each requirement's result and the drop-one-signature experiment, then
emits `PASS`/`FAIL`. The suite's own expectation is stored per fixture in
`expected_independence.rubric_verdict`; the verifier's exit code is 0 iff every fixture's
computed verdict matches its declared expectation. The three-fixture suite pins all three
verdicts at once: `valid-composition.json` PASSes (binding, no copy), `copy-with-binding.json`
PASSes (copy **plus** resolving binding — the R4 permitted case), and
`laundered-authority.json` is correctly FAILed (bare copy, no binding).

## 6. Mapping to CTEF's existing negative-path vocabulary

This rubric reuses CTEF's established structural-before-semantic, fail-closed discipline and
its content-addressed error family (`src/trust/ctef_error_codes.py`,
`src/trust/action_ref_vectors.py`):

| Rubric requirement | Related CTEF error code | Layer |
|---|---|---|
| R1 per-spec verification | `INVALID_SIGNATURE_INPUT`, `CANONICALIZATION_MISMATCH` | wire |
| R3 drop-one-signature | `INVALID_COMPOSITION` (leg not load-bearing) | authority |
| R4 bare self-asserted copy | `INVALID_CLAIM_SCOPE` (claim carries authority it may not assert) | authority |
| R5 binding integrity | `RESCOPED_REPLAY`, `AMBIGUOUS_ISSUER_BINDING` | correlation |

All are structural failures returned **before** any policy evaluation, fail-closed by
construction — the same posture CTEF already publishes at
`/.well-known/ctef-error-codes.json`.

## 7. Independent convergence / prior art

A second, unrelated working group derived the same invariant independently, from the opposite
direction and on a different signature curve. `trustless-ai/cross-reference-console` **PR #8**
("spec: derive lane distinctness instead of trusting the label") builds a mutual-recompute mesh
where an *edge* holds only when ≥2 signed **cells** recompute a byte-equal `claim_id` on
genuinely **distinct implementations**. Its cells are signed with **BIP340 (secp256k1 Schnorr,
Nostr envelope)** — not CTEF's Ed25519 — and it arrives at the same design requirement while
guarding a different threat (correlated implementations that *share bugs*, rather than authority
laundered across specs).

The convergent rule, in their words (giskard09, adopted verbatim into the PR's proposal §6.1),
is a near-exact restatement of what R4/R5 exist to enforce:

> *never collapse multiple provenance facts into a field where the signer has to omit or pick one*

and the failure they name is the same one:

> *a qualifying state travelling as prose beside the value instead of inside the structure*

In their case the "qualifying state" was a **non-derivation** claim ("re-derived from the spec,
**not** from `reference/claim_id.py` … reasoned from CLAIM.md") that one operator had disclosed
by hand inside a free-text boundary string, because the signed struct had nowhere to put it.
Their fix is to promote it to a **required, enumerated `derived_from` list inside the signed
struct** — a *list* precisely so that a signer who drew on two implementations cannot be forced
to name one and omit the other, and `[]`≠absent so silence can never read as independence.

### 7.1 Mapping their formulation to these requirements

| trustless-ai/cross-reference-console PR #8 | this rubric |
|---|---|
| "never collapse multiple provenance facts into a field where the signer has to pick one" | **R4** — a cross-leg fact MUST NOT be carried by a *bare* self-asserted copy the signer fills in; the dependency must ride a content-addressed reference the signer cannot forge (a copy is tolerated only as decoration beside that reference) |
| `derived_from` is a **required list inside the signed struct**; `[]`≠absent; absence fails the gate | **R5** — the cross-leg binding lives **inside B's signed preimage** as `authority_ref`; a missing / unresolved ref is fail-closed |
| an edge closes only on genuinely distinct, non-derived lanes | **R3** — the composite passes only if each gating leg is independently load-bearing (**drop-one ⇒ deny**) |
| "could-not-check is never a pass" — reads AMBER, never GREEN | R3/R5 fail-closed: any unresolved dependency ⇒ `FAIL` |
| same discipline as `action_ref` / `decision_binding_ref` | §6 mapping to CTEF's `action_ref` error vocabulary |

### 7.2 Why two implementations make this a design law, not a convention

Two independent implementations — **different working group, different threat model**
(implementation-independence vs. authority-laundering), **different signature curve** (BIP340 vs.
Ed25519), no shared code and no shared author — landing the same *"don't let the signer collapse
a provenance fact into a field they pick"* constraint is strong evidence the criterion is a
**design law**, not a house convention. A convention would not reappear unprompted in a codebase
that shares nothing with this one. Both, notably, reject the identical anti-pattern: a fact that
matters living **beside** the signed bytes as prose the signer controls, instead of **inside**
them as a content-addressed / enumerated element the signer cannot quietly collapse.

### 7.3 Where the two differ (recorded, not smoothed over)

The convergence is on the **principle**; the object and the maturity differ, and flattening that
would be the very error §7.2 warns against:

- **Object.** trustless-ai apply the law to a **single cell's self-declared lineage** (*is this
  implementation derived from another?*) — an honesty/completeness property on one signer's own
  provenance. This rubric applies it **across legs** (*does B's authority actually come from A's
  signature?*) — a cryptographic load-bearing property spanning two signers.
- **Maturity.** In PR #8 the no-collapse half is still a **proposal** (`crc.cell.v3`): only the
  *necessary* conditions (`impl_hash`/`repo` present-and-distinct) are enforced in code today,
  and the sufficient `derived_from` field is disclosed-or-absent — "absent" reads AMBER, not
  pass. This rubric's `verify.py` runs the full **drop-one-signature** experiment end-to-end
  today, not as a proposal.

Same law, two layers, two levels of enforcement maturity.

## 8. Open alignment items (to settle with the lab / Pablo)

These do not block the rubric or the fixtures from running as-is, but they are the cross-spec
choices the lab and CTEF/argentum maintainers should ratify before partners pin to the profile.

1. **`authority_ref` domain-separation prefix.** Today `authority_ref` is the plain
   `sha256:` of the referenced slot's RFC 8785 JCS preimage, with **no domain-separation tag**.
   A separate argentum `action-ref` line of work uses a domain-tagged preimage
   (`mycelium.action-ref:v2:` was mentioned at commit `96931c9`); that tag is **not present in
   this repo's CTEF substrate** (the CTEF `action_ref` preimage carries no domain prefix), so the
   rubric does not adopt it. **Open question:** should the lab standardize a domain-separation
   prefix for `authority_ref`, and if so which one and which spec owns it? Until settled, the
   rubric and `verify.py` stay on the untagged content-addressed hash. Adopting a prefix later is
   a one-line change to the preimage in `generate_fixtures.py` + `verify.py` and a regeneration;
   no requirement (R1–R5) changes.
2. **CTEF version to cite.** This rubric pins **v0.3.2** (settled). v0.3.3 is additive,
   backward-compatible and maintainer-approved but CTEF-scoped with cross-spec pieces in flight.
   Confirm whether the lab wants the normative citation moved to 0.3.3 once its cross-spec pieces
   land.
3. **Profile string.** The tag is `ctef-independence-v0`. Some argentum artifacts use
   frozen-profile names like `…-v1-jcs-sha256`. Confirm the lab's preferred convention before
   partners pin to the string.
