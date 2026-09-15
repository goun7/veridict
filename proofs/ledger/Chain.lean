/-
  Veridict ledger chaining (§4.1, §2.3) — formal model and UNBOUNDED proofs.
  The sibling lane of proofs/ladder; same doctrine, same rules of engagement.

  What the model abstracts (disclosed, not hidden):
  * Hashes (payload digest `pd`, entry hash `H`) are UNINTERPRETED functions
    over an arbitrary decidable type `V`. Python instantiates them with
    SHA-256 over the canonical §2.3 preimage. We deliberately prove the
    STRUCTURAL guarantees that hold for ANY `H`; wherever tamper-detection
    genuinely needs hash behavior, the theorem states it as an explicit
    hypothesis (`pd p' ≠ e.ph`, `H r p' ≠ e.eh`) — that is exactly the
    collision request, and nothing beyond it is claimed.
  * `seq`, `entry_type`, `author`, `ts`, `schema_version` are preimage
    components in Python; the model folds them into the payload slot of H
    because verify_chain checks NOTHING about them except through the
    recomputed hash — positional binding is enforced by the prev-chain,
    which is precisely what C5/C6 prove.
  * The three per-entry checks are conjoined here; Python evaluates them in
    order only to phrase its diagnostic message. The BOOLEAN verdict — the
    thing certificates and CI consume — is order-independent. The ladder
    lane shows what branch-order fidelity is done FOR (value-level
    enumeration); this lane proves relational structure instead, so the
    absence of a truth table here is by design, not omission.
  * Proof style: structural induction over arbitrary-length lists; no
    `decide`-cascades, no `native_decide`, no sorry.

  Theorems (verifyGo mirrors verify_chain's three checks per entry):
    C1 empty-verifies       — vacuous chain verifies (fail-safe orientation)
    C2 wellformed-accepted  — every honestly minted chain verifies from any
                              starting link: writer and reader agree by
                              construction; no valid ledger is ever rejected
    C3 prefix-closed        — validity of a whole gives validity of any
                              prefix: detection never DEPENDS on later
                              entries; suffix edits cannot launder a corrupt
                              prefix
    C4 payload-edit         — edit a stored payload without re-minting its
                              digest ⇒ detected at that entry; no hash
                              assumption needed
    C5 remint-needs-        — strongest adversary: replace a link with an
       collision               honestly re-minted entry (fresh payload,
                              fresh digest, fresh hash over the same
                              predecessor). The NEXT link catches it modulo
                              exactly `H r p' ≠ e.eh` — the collision
                              request, stated. Mid-chain positions reduce to
                              this head form by congruence: the unedited
                              prefix is the same list started at the same
                              predecessor in both runs, hence leaves the
                              same running head for the edited suffix.
    C6 prev-rooted          — a head not bound to its claimed predecessor
                              fails at position 0; instantiated at GENESIS,
                              no ledger fragment is portable onto a forged
                              past.

  Axiom audit (measured with `#print axioms`, Lean v4.34.0, 2026-09-15):
    C1: NO axioms.  C2–C6: [propext] only — pulled in by Boolean-logic
    simp rewrites (Bool.and_eq_true / beq_iff_eq), the standard benign
    dependency. `Classical.choice`, `sorryAx`, `native_decide` appear
    nowhere in this lane; there is not even a `decide` — every proof is
    structural induction over arbitrary lists.
-/

namespace Chain

structure Entry (α V : Type) where
  payload : α
  prev    : V
  ph      : V
  eh      : V

/-- The verify_chain walk: payload hash, entry hash over the RUNNING
    predecessor, raw prev-link; continue from the (now confirmed) hash. -/
def verifyGo [DecidableEq V] (pd : α → V) (H : V → α → V) :
    V → List (Entry α V) → Bool
  | _, [] => true
  | prev, e :: rest =>
      if e.ph == pd e.payload && e.eh == H prev e.payload && e.prev == prev then
        verifyGo pd H e.eh rest
      else false

/-- The ledger's own minting (§4.1). -/
def mint [DecidableEq V] (pd : α → V) (H : V → α → V) (prev : V) (p : α) :
    Entry α V :=
  { payload := p, prev := prev, ph := pd p, eh := H prev p }

def buildGo [DecidableEq V] (pd : α → V) (H : V → α → V) :
    V → List α → List (Entry α V)
  | _, [] => []
  | prev, p :: ps => mint pd H prev p :: buildGo pd H (H prev p) ps

variable {α V : Type} [DecidableEq V] (pd : α → V) (H : V → α → V)

/-- One verification step unpacked into usable hypotheses. -/
private theorem goCons {prev : V} {e : Entry α V} {rest : List (Entry α V)} :
    verifyGo pd H prev (e :: rest) = true ↔
      (e.ph = pd e.payload ∧ e.eh = H prev e.payload ∧ e.prev = prev
        ∧ verifyGo pd H e.eh rest = true) := by
  rw [verifyGo]
  by_cases h1 : e.ph == pd e.payload
  · by_cases h2 : e.eh == H prev e.payload
    · by_cases h3 : e.prev == prev
      · rw [if_pos (by simp [h1, h2, h3])]
        exact ⟨fun ht => ⟨by simpa using h1, by simpa using h2, by simpa using h3, ht⟩,
              fun ⟨_, _, _, ht⟩ => ht⟩
      · rw [if_neg (by simp [h3])]
        exact ⟨fun hh => by simp_all, fun ⟨_, _, hp, _⟩ => absurd hp (by simpa using h3)⟩
    · rw [if_neg (by simp [h2])]
      exact ⟨fun hh => by simp_all, fun ⟨_, hq, _, _⟩ => absurd hq (by simpa using h2)⟩
  · rw [if_neg (by simp [h1])]
    exact ⟨fun hh => by simp_all, fun ⟨hp, _, _, _⟩ => absurd hp (by simpa using h1)⟩

theorem C1_empty_verifies (prev : V) : verifyGo pd H prev [] = true := rfl

theorem C2_wellformed_accepted (prev : V) :
    ∀ xs : List α, verifyGo pd H prev (buildGo pd H prev xs) = true := by
  intro xs
  induction xs generalizing prev with
  | nil => exact rfl
  | cons p ps ih =>
      have step : verifyGo pd H prev (mint pd H prev p :: buildGo pd H (H prev p) ps)
          = verifyGo pd H (H prev p) (buildGo pd H (H prev p) ps) := by
        rw [verifyGo, if_pos (by simp [mint])]
        simp [mint]
      rw [buildGo, step]
      exact ih (H prev p)

/-- Suffix-independent detection: the running head carried through `as`
    is identical in `as ++ bs` and in `as` alone. -/
theorem C3_prefix_closed (as bs : List (Entry α V)) (prev : V)
    (h : verifyGo pd H prev (as ++ bs) = true) :
    verifyGo pd H prev as = true := by
  induction as generalizing prev with
  | nil => exact rfl
  | cons a as ih =>
      simp only [List.cons_append] at h
      obtain ⟨h1, h2, h3, htail⟩ := (goCons (pd := pd) (H := H)).mp h
      rw [verifyGo, if_pos (by simp [h1, h2, h3])]
      exact ih a.eh htail

/-- Payload edited in place; the stale stored digest reports it there. -/
theorem C4_payload_edit_detected (as tail : List (Entry α V)) (e : Entry α V)
    (p' : α) (prev : V) (hd : pd p' ≠ e.ph)
    (h : verifyGo pd H prev (as ++ [e] ++ tail) = true) :
    verifyGo pd H prev (as ++ [{ e with payload := p' }] ++ tail) = false := by
  induction as generalizing prev with
  | nil =>
      show verifyGo pd H prev ({ e with payload := p' } :: tail) = false
      rw [verifyGo]
      refine if_neg ?_
      intro hpe
      simp only [Bool.and_eq_true] at hpe
      exact hd ((by simpa using hpe.1.1 : e.ph = pd p').symm)
  | cons a as ih =>
      simp only [List.cons_append] at h ⊢
      obtain ⟨h1, h2, h3, htail⟩ := (goCons (pd := pd) (H := H)).mp h
      rw [verifyGo]
      rw [if_pos (by simp [h1, h2, h3])]
      exact ih a.eh htail

/-- The honest-remint adversary: caught by the next raw link, modulo a
    collision at the replaced entry. -/
theorem C5_remint_needs_collision (e f : Entry α V) (tail : List (Entry α V))
    (p' : α) (r : V) (hH : H r p' ≠ e.eh)
    (hv : verifyGo pd H r (e :: f :: tail) = true) :
    verifyGo pd H r (mint pd H r p' :: f :: tail) = false := by
  obtain ⟨_, _, _, hrest⟩ := (goCons (pd := pd) (H := H)).mp hv
  obtain ⟨h4, _, hfp, _⟩ := (goCons (pd := pd) (H := H)).mp hrest
  have hhead : verifyGo pd H r (mint pd H r p' :: f :: tail)
      = verifyGo pd H (H r p') (f :: tail) := by
    rw [verifyGo, if_pos (by simp [mint])]
    simp [mint]
  rw [hhead, verifyGo]
  refine if_neg ?_
  intro hc
  simp only [Bool.and_eq_true] at hc
  exact hH ((by simpa [hfp] using hc.2 : e.eh = H r p').symm)

/-- Chains cannot be re-rooted: the head's raw link binds it to its past. -/
theorem C6_prev_rooted (e : Entry α V) (tail : List (Entry α V)) (prev : V)
    (hp : e.ph = pd e.payload) (he : e.eh = H prev e.payload) (hr : e.prev ≠ prev) :
    verifyGo pd H prev (e :: tail) = false := by
  rw [verifyGo]
  refine if_neg ?_
  intro hc
  simp only [Bool.and_eq_true] at hc
  exact hr (by simpa using hc.2)

end Chain
