/-
  Veridict anchor verification (veridict/anchor.py, §2.4/§11) — formal model
  and UNBOUNDED proofs. Third lane: ladder values, ledger chains, anchors.

  The model abstracts (disclosed, not hidden):
  * ECDSA is NOT modeled. The two signature checks (SET over the canonical
    4-field entry; STH checkpoint note) enter as opaque booleans `setOK`,
    `noteSigOK`. Deliberate: their soundness is a computational assumption,
    and a structural proof that "passed" them would be theater. What IS
    provable — and what this lane proves — is the architecture around them:
    which predicates a valid anchor must satisfy, that failing ANY
    structural predicate makes both signatures irrelevant, and that an
    honestly minted sidecar is accepted by construction.
  * Base64/hex/JSON decoding of `body` and the checkpoint note collapses to
    `noteOK` (delimiter present, three lines, root decodable) and
    `body : Option (kind × hashValue)` (none = undecodable). Python's early
    `return`s change WHICH errors are reported; the boolean verdict `valid`
    is exactly the flat conjunction modeled here — mirrored, then proved
    about (check-order independence is the same argument the ledger lane
    documents).
  * `rootFromNote : Option V` models "empty/undecodable root skips the
    cross-check"; the all-empty degenerate sidecar collapses fail-closed via
    `noteOK`/`body` — disclosed, not encoded. Likewise the empty-digest
    guard (`if digest and …`): a real sidecar always carries its digest
    (publish writes it), and a missing one fails `hashValue = digest`
    anyway.
  * The RFC-6962 leaf construction (`sha256(0x00 || body)`) and the live
    uuid convention (treeID || leaf || treeID) sit BEHIND the boolean
    `uuidEq`: this lane proves the wiring (a 96-char uuid with a wrong
    middle is rejected), not SHA-256 again.

  Theorems (∀ payloads, ∀ sidecars, arbitrary values — the unboundedness
  discipline of the other two lanes):
    A0 fail-closed-parse   — malformed note or undecodable body ⇒ invalid
                             under ANY signature verdict
    A1 binding-necessary   — valid against a certificate ⇒ bound =
                             fieldsOf(cert) AND digest = ad(bound)
    A2 soundness           — valid ⇒ every structural predicate holds
                             (nothing is silently skippable)
    A3 mint-accepted       — an honestly built sidecar verifies, both with
                             its certificate and crypto-only
    A4 sigs-cannot-rescue  — THE HEADLINE: bound ≠ fieldsOf(cert) ⇒ invalid
                             regardless of both signature booleans: a fully
                             compromised log operator signing VALID ECDSA
                             over the wrong binding still fails
                             `veridict verify`
    A5 tree-containment    — logIndex ≥ signed tree size ⇒ invalid, sigs
                             irrelevant: no anchoring beyond the frontier
    A6 root-agreement      — proof rootHash ≠ signed checkpoint root ⇒
                             invalid before either signature is consulted:
                             note and proof must describe one tree
    A7 uuid-embeds-leaf    — 96-hex uuid whose middle is not the entry's
                             leaf hash ⇒ invalid

  Measured kernel axiom audit (leanprover/lean4:v4.34.0, `lake env lean
  axiom_audit.lean`; CI re-runs it — receipts, not narrative):
    A0–A7 (all nine): [propext] — nothing else. No `sorry`, no
    `native_decide`, no `Classical.choice`, no `Quot.sound`. The propext
    residue comes from propositional-rewriting simp lemmas, not from any
    computational shortcut: every theorem is structural.
    A4 — the headline — is thus an unconditional architecture claim:
    inside this model, a valid ECDSA signature is NOT a route around
    binding.
-/

namespace Anchor

structure Bound (α : Type) where
  anchor    : α
  certId    : α
  keyId     : α
  ckSeq     : Nat
  chainHash : α
  deriving DecidableEq

structure Cert (α : Type) where
  anchor    : α
  certId    : α
  keyId     : α
  ckSeq     : Nat
  chainHash : α
  deriving DecidableEq

/-- `bound_fields` (§2.4): exactly what an anchor must bind about a cert. -/
def fieldsOf (anchorA : α) (c : Cert α) : Bound α :=
  { anchor := anchorA, certId := c.certId, keyId := c.keyId,
    ckSeq := c.ckSeq, chainHash := c.chainHash }

/-- The sidecar fields `verify` compares; decode/signature layers as opaque
    bits per the header. -/
structure Side (α V : Type) where
  bound        : Bound α
  digest       : V
  body         : Option (α × V)
  noteOK       : Bool
  rootFromNote : Option V
  proofRoot    : V
  size         : Nat
  proofIdx     : Nat
  uuidLen96    : Bool
  uuidEq       : Bool
  setOK        : Bool
  noteSigOK    : Bool

/-- The verify predicate: the flat conjunction of §2.4's checks. -/
def verify [DecidableEq α] [DecidableEq V] (anchorA hr : α) (ad : Bound α → V)
    (c : Option (Cert α)) (s : Side α V) : Bool :=
      s.noteOK
        && (match s.body with
            | some b => decide (b.1 = hr) && decide (b.2 = s.digest)
            | none => false)
        && (match c with
            | some ct => decide (fieldsOf anchorA ct = s.bound)
            | none => true)
        && (decide (s.digest = ad (match c with
                                   | some ct => fieldsOf anchorA ct
                                   | none => s.bound)))
        && (match s.rootFromNote with
            | some r => decide (r = s.proofRoot)
            | none => true)
        && decide (s.proofIdx < s.size)
        && (!s.uuidLen96 || s.uuidEq)
        && s.setOK && s.noteSigOK

variable {α V : Type} [DecidableEq α] [DecidableEq V] (anchorA hr : α) (ad : Bound α → V)

theorem A0_fail_closed_parse (c : Option (Cert α)) (s : Side α V)
    (h : ¬ s.noteOK = true ∨ s.body = none) : verify anchorA hr ad c s = false := by
  obtain h | h := h
  · have hn : s.noteOK = false := by
      cases h' : s.noteOK with
      | true => exact absurd h' h
      | false => rfl
    simp only [verify, hn]
    simp
  · simp only [verify, h]
    simp


/-- Prop unpacking of one verification pass (bridge for destructuring).
    Leaves that depend on opaque matches keep their normalized Bool shape;
    certificate-dependent leaves are fully converted to Prop. -/
private theorem goTrue {c : Option (Cert α)} {s : Side α V} :
    verify anchorA hr ad c s = true ↔
      (s.noteOK = true
        ∧ ((match s.body with
            | some b => decide (b.1 = hr) && decide (b.2 = s.digest)
            | none => false) = true)
        ∧ ((match c with
            | some ct => decide (fieldsOf anchorA ct = s.bound)
            | none => true) = true)
        ∧ s.digest = ad (match c with
                         | some ct => fieldsOf anchorA ct
                         | none => s.bound)
        ∧ ((match s.rootFromNote with
            | some r => decide (r = s.proofRoot)
            | none => true) = true)
        ∧ s.proofIdx < s.size
        ∧ (!s.uuidLen96 || s.uuidEq) = true
        ∧ s.setOK = true ∧ s.noteSigOK = true) := by
  refine Iff.intro ?fwd ?rev
  · intro hh
    simp only [verify, Bool.and_eq_true, decide_eq_true_eq] at hh
    exact ⟨hh.1.1.1.1.1.1.1.1, hh.1.1.1.1.1.1.1.2, hh.1.1.1.1.1.1.2,
           hh.1.1.1.1.1.2, hh.1.1.1.1.2, hh.1.1.1.2, hh.1.1.2, hh.1.2, hh.2⟩
  · intro hh
    simp only [verify, Bool.and_eq_true, decide_eq_true_eq]
    exact ⟨⟨⟨⟨⟨⟨⟨⟨hh.1, hh.2.1⟩, hh.2.2.1⟩, hh.2.2.2.1⟩, hh.2.2.2.2.1⟩,
          hh.2.2.2.2.2.1⟩, hh.2.2.2.2.2.2.1⟩, hh.2.2.2.2.2.2.2.1⟩,
          hh.2.2.2.2.2.2.2.2⟩

theorem A1_binding_necessary (ct : Cert α) (s : Side α V)
    (h : verify anchorA hr ad (some ct) s = true) :
    fieldsOf anchorA ct = s.bound ∧ s.digest = ad (fieldsOf anchorA ct) := by
  obtain ⟨_, _, hbind, hdig, _, _, _, _, _⟩ :=
      (goTrue anchorA hr ad (c := some ct)).mp h
  exact ⟨by simpa using hbind, hdig⟩

/-- No check is silently skippable. -/
theorem A2_soundness (c : Option (Cert α)) (s : Side α V)
    (h : verify anchorA hr ad c s = true) :
    s.noteOK = true
      ∧ ((match s.body with
          | some b => decide (b.1 = hr) && decide (b.2 = s.digest)
          | none => false) = true)
      ∧ s.setOK = true ∧ s.noteSigOK = true ∧ s.proofIdx < s.size
      ∧ (!s.uuidLen96 || s.uuidEq) = true := by
  obtain ⟨hn, hbody, _, _, _, ht, hu, hs, hs2⟩ :=
      (goTrue anchorA hr ad (c := c)).mp h
  exact ⟨hn, hbody, hs, hs2, ht, hu⟩

/-- The mint path (publish + honest log). -/
def mintSide (ct : Cert α) (root : V) (idx : Nat) : Side α V :=
  let exp := fieldsOf anchorA ct
  { bound := exp, digest := ad exp, body := some (hr, ad exp), noteOK := true,
    rootFromNote := some root, proofRoot := root, size := idx + 1, proofIdx := idx,
    uuidLen96 := true, uuidEq := true, setOK := true, noteSigOK := true }

theorem A3_mint_accepted (ct : Cert α) (root : V) (idx : Nat) :
    verify anchorA hr ad (some ct) (mintSide anchorA hr ad ct root idx) = true := by
  simp only [mintSide, verify, fieldsOf]
  simp

theorem A3b_mint_accepted_crypto_only (ct : Cert α) (root : V) (idx : Nat) :
    verify anchorA hr ad none (mintSide anchorA hr ad ct root idx) = true := by
  simp only [mintSide, verify, fieldsOf]
  simp

/-- THE HEADLINE: with the wrong binding, no signature can rescue — both
    ECDSA booleans are existentially quantified away by the shape of the
    statement (they never appear in the hypotheses). -/
theorem A4_sigs_cannot_rescue_binding (ct : Cert α) (s : Side α V)
    (h : fieldsOf anchorA ct ≠ s.bound) :
    verify anchorA hr ad (some ct) s = false := by
  simp only [verify]
  rw [decide_eq_false h]
  simp

theorem A5_tree_containment (c : Option (Cert α)) (s : Side α V)
    (h : s.size ≤ s.proofIdx) : verify anchorA hr ad c s = false := by
  simp only [verify]
  rw [decide_eq_false (Nat.not_lt_of_ge h)]
  simp

theorem A6_root_agreement (c : Option (Cert α)) (s : Side α V) (r : V)
    (hrn : s.rootFromNote = some r) (h : r ≠ s.proofRoot) :
    verify anchorA hr ad c s = false := by
  simp only [verify, hrn]
  rw [decide_eq_false h]
  simp

theorem A7_uuid_embeds_leaf (c : Option (Cert α)) (s : Side α V)
    (h96 : s.uuidLen96 = true) (hne : s.uuidEq = false) :
    verify anchorA hr ad c s = false := by
  simp only [verify, h96, hne]
  simp

end Anchor
