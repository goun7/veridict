/-
  Veridict adjudication ladder (§6.1) — formal model and UNBOUNDED proofs.

  Issue #8 asked for the guarantees that `scripts/verify_ladder.py` only
  *sampled*: the bounded receipt (docs/receipts-ladder-verification.json,
  28,080 cases, evidence length ≤ 3) enumerates a finite input space; this
  file proves the same properties for evidence lists of ARBITRARY length,
  over an idealized model of veridict/ladder.py + veridict/divergence.py.

  Honest scope (receipts, not narrative):
  * This is a model OF the Python, not a verification OF the Python.
    Fidelity rests on two receipts: (1) TruthTable.lean (generated from the
    bounded harness by scripts/export_lean_truth_table.py) re-checks THIS
    Lean function against all 28,080 recorded cases at build time — any
    divergence inside the sampled domain fails the build; (2) the
    ladder.py source hash beside the table ties it to the shipped code.
  * Divergence tolerance is fixed at 1/3 (standard default) with exact
    integer arithmetic (`3 · minority ≤ n`); the Python's IEEE floats agree
    on every equality boundary inside the sampled domain — asserted by
    the same truth table, not by hand-waving.
  * I8 (determinism) and I9 (domain closure) are true BY CONSTRUCTION here
    (total pure functions into closed types) and recorded as such rather
    than restated as theorems. The Python counterparts are runtime-checked.
  * The cross-check uses `native_decide` — kernel-trusted execution of the
    checker on literal data; the trust placement is disclosed, and the
    general theorems below do NOT rely on it.
  Axiom audit (`#print axioms` on Lean v4.34.0, measured not asserted):
    I1, I7            : NO axioms at all
    I5, I6, I10       : [propext]
    I2, I4            : [propext, Quot.sound]
  — no sorryAx, no Classical.choice, no native_decide anywhere in the
  general lane; the oracle lane (`rowLen`, `agree` in TruthTable.lean)
  depends on the disclosed native_decide axiom, visible by name in the
  proofs.yml CI log.
-/

set_option maxHeartbeats 2000000

namespace Ladder

inductive Tier where
  | w1a | w1b | w2 | w3
  deriving DecidableEq, Repr

inductive Stance where
  | supports | refutes
  deriving DecidableEq, Repr

/-- One piece of evidence, reduced to what the ladder actually reads. -/
abbrev Ev := Tier × Stance

inductive Verdict where
  | verified | refuted | inconclusive | escalated
  deriving DecidableEq, Repr

inductive Div where
  | unanimous | majority | split
  deriving DecidableEq, Repr

inductive Rung where
  | r0 | r1 | r2 | r3 | r4
  deriving DecidableEq, Repr

/-- Lean core (no Std/Mathlib) emptiness flags. -/
def emptyB {α : Type} (l : List α) : Bool := match l with | [] => true | _ :: _ => false
def nonemptyB {α : Type} (l : List α) : Bool := !emptyB l

def w1a (e : List Ev) : List Ev := e.filter (fun x => x.1 == .w1a)
def w1b (e : List Ev) : List Ev := e.filter (fun x => x.1 == .w1b)
def w2plus (e : List Ev) : List Ev :=
  e.filter (fun x => x.1 == .w2 || x.1 == .w3)

def refutesIn (l : List Ev) : Bool := l.any (fun x => x.2 == .refutes)
def supportsIn (l : List Ev) : Bool := l.any (fun x => x.2 == .supports)
/-- Stances are exhaustive and exclusive, so "all support" is "none refute". -/
def allSupport (l : List Ev) : Bool := !refutesIn l

/-- veridict/divergence.py at tolerance 1/3, exact rational arithmetic:
    minority/n ≤ 1/3 ⟺ 3·min ≤ n. -/
def divergence (e : List Ev) : Div :=
  let d := w2plus e
  let n := d.length
  let sup := (d.filter (fun x => x.2 == .supports)).length
  let ref := n - sup
  if n = 0 || sup = 0 || ref = 0 then .unanimous
  else if 3 * min sup ref ≤ n then .majority else .split

structure Out where
  value : Verdict
  div : Div
  rung : Rung
  /-- §4.4.3: a first-round split stays visible even after consensus. -/
  splitNoted : Bool
  /-- meta-claim depths emitted (§6.1), mirroring ladder.py's `metas`. -/
  metaDepths : List Nat
  deriving DecidableEq, Repr

/-- The ladder's control flow with every evidence-derived quantity as an
    explicit Bool — the decidable shape the general theorems run on.
    `metaOn` abstracts `1 ≤ budget`. -/
def adjudicateCore (machine crit polCrit metaOn frs : Bool) (div : Div)
    (empty anyRef hasW1a w1aSup w1aAll w1aRef w1bRef w1bSup w2pRef w2pAll hasW2 : Bool) : Out :=
  let meta1 : List Nat := if metaOn then [1] else []
  if empty then
    ⟨.inconclusive, div, .r4, frs, []⟩
  else if machine && w1aSup && w1aAll && !anyRef then
    ⟨.verified, div, .r0, frs, meta1⟩
  else if hasW1a then
    if w1aRef then ⟨.refuted, div, .r1, frs, []⟩
    else if w1bRef then ⟨.verified, div, .r2, frs, meta1⟩
    else ⟨.verified, div, .r1, frs, if w2pRef then meta1 else []⟩
  else if w1bRef then
    ⟨.inconclusive, div, .r2, frs, meta1⟩
  else if crit && polCrit && div == .split then
    ⟨.escalated, div, .r3, frs, []⟩
  else if hasW2 then
    if div == .split then ⟨.inconclusive, div, .r4, frs, []⟩
    /- Erratum D14 (§5.3 rule 1): W1b deterministic static truth outranks W2
       doctrine. A W1b SUPPORT cannot be overturned into REFUTED by a juror's
       disagreement — the real-LLM canary measured 3B models REFUTE claims
       they cannot evidence, and letting that dissent decide produced false
       positives on clean code. W1b support keeps the claim VERIFIED; the
       dissent stays visible in the divergence field rather than promoted
       into the verdict. Without this clause the model and ladder.py disagree
       on one of the 28080 recorded cases and the truth-table build fails
       (D21) — the formal core silently described the pre-D14 ladder. -/
    else if w1bSup then ⟨.verified, div, .r4, frs, []⟩
    else ⟨if w2pAll then .verified else .refuted, div, .r4, frs, []⟩
  else
    ⟨.inconclusive, div, .r4, frs, []⟩

/-- veridict/ladder.py::adjudicate. Claim fields the ladder reads:
    `machine` = verifiability is MACHINE_CHECKABLE; `crit` = the claim's
    critical_class is CRITICAL; `polCrit` = CRITICAL ∈ policy.criticality;
    `budget` = policy thresholds.meta_claim_depth_budget. -/
def adjudicate (machine crit polCrit : Bool) (budget : Nat) (frs : Bool)
    (e : List Ev) : Out :=
  adjudicateCore machine crit polCrit (decide (1 ≤ budget)) frs (divergence e)
    (emptyB e) (refutesIn e) (nonemptyB (w1a e)) (supportsIn (w1a e)) (allSupport (w1a e))
    (refutesIn (w1a e)) (refutesIn (w1b e)) (supportsIn (w1b e))
    (refutesIn (w2plus e))
    (allSupport (w2plus e)) (e.any (fun x => x.1 == .w2))

/-! ## Linking lemmas: Bool flags ↔ lists -/

theorem emptyB_true_iff_nil {α : Type} {l : List α} (h : emptyB l = true) : l = [] := by
  cases l with
  | nil => rfl
  | cons _ _ => simp [emptyB] at h

theorem nonemptyB_isNe {α : Type} {l : List α} (h : nonemptyB l = true) : l ≠ [] := by
  intro hl; subst hl; simp [nonemptyB, emptyB] at h

theorem any_eq_true {l : List Ev} {p : Ev → Bool} (h : l.any p = true) :
    ∃ x ∈ l, p x = true := List.any_eq_true.mp h

theorem any_filter_imp_any {l : List Ev} {p q : Ev → Bool}
    (h : (l.filter p).any q = true) : l.any q = true := by
  obtain ⟨x, hx, hq⟩ := List.any_eq_true.mp h
  exact List.any_eq_true.mpr ⟨x, (List.mem_filter.mp hx).1, hq⟩

theorem not_allSupport_refutes {l : List Ev} (h : refutesIn l = true) :
    allSupport l = false := by
  simp [allSupport, h]

theorem allSupport_true_imp_refutes_false {l : List Ev}
    (h : allSupport l = true) : refutesIn l = false := by
  cases h' : refutesIn l with
  | false => rfl
  | true  => have hh := not_allSupport_refutes h'; simp_all

theorem supportsIn_imp_has {l : List Ev} (h : supportsIn l = true) :
    nonemptyB l = true := by
  cases l with
  | nil => simp [supportsIn, List.any] at h
  | cons _ _ => rfl

theorem refutesIn_imp_has {l : List Ev} (h : refutesIn l = true) :
    nonemptyB l = true := by
  cases l with
  | nil => simp [refutesIn, List.any] at h
  | cons _ _ => rfl

theorem nonemptyB_filter {l : List Ev} {p : Ev → Bool}
    (h : nonemptyB (l.filter p) = true) : nonemptyB l = true := by
  cases l with
  | nil => simp [List.filter, nonemptyB, emptyB] at h
  | cons _ _ => rfl

/-! ## The general theorems (arbitrary-length evidence, §6.1 invariants)

    Shape of every proof: a `key` lemma quantified over ALL ladders — core
    arguments plus the evidence flags, with the list-derived facts passed
    as flag equalities — closed by `decide` (finite: 2^13 × 3 shapes),
    then applied to the concrete flags of `adjudicate`. The theorems
    themselves are about arbitrary lists. -/

/-- I1 — fail-safe on emptiness (§4.3 rule 5): no evidence is never a
    silent pass; INCONCLUSIVE @ R4, machine or not. -/
theorem I1_fail_safe_empty (machine crit polCrit : Bool) (budget : Nat) (frs : Bool) :
    (adjudicate machine crit polCrit budget frs []) =
      ⟨.inconclusive, .unanimous, .r4, frs, []⟩ := by
  -- every flag of the empty list computes to a literal; the core is then a
  -- closed Bool/Div term and `decide` discharges the whole walk.
  -- empty flag short-circuits the walk before meta1 matters; the RHS is
  -- definitional.
  unfold adjudicate
  rfl

/-- I2 — no silent pass: VERIFIED requires machine (W1a) or reproducible
    static (W2) evidence; doctrine W3 alone can never verify. Unbounded. -/
theorem I2_no_silent_pass (machine crit polCrit : Bool) (budget : Nat) (frs : Bool)
    (e : List Ev) (h : (adjudicate machine crit polCrit budget frs e).value = .verified) :
    w1a e ≠ [] ∨ ∃ x ∈ e, x.1 == .w2 := by
  have key : ∀ (m c p mo f : Bool) (d : Div)
      (emp anyRef hA sup al ref b supB w2r w2a w2 : Bool),
      (sup = true → hA = true) →
      (adjudicateCore m c p mo f d emp anyRef hA sup al ref b supB w2r w2a w2).value =
        .verified →
      hA = true ∨ w2 = true := by
    intro m c p mo f d emp anyRef hA sup al ref b supB w2r w2a w2 link hv
    cases d <;>
      revert m c p mo f emp anyRef hA sup al ref b supB w2r w2a w2 link hv <;> decide
  obtain (hA | hw2) :=
    key machine crit polCrit (decide (1 ≤ budget)) frs (divergence e) (emptyB e)
      (refutesIn e) (nonemptyB (w1a e)) (supportsIn (w1a e)) (allSupport (w1a e)) (refutesIn (w1a e))
      (refutesIn (w1b e)) (supportsIn (w1b e))
      (refutesIn (w2plus e)) (allSupport (w2plus e))
      (e.any (fun x => x.1 == .w2))
      (fun hs => supportsIn_imp_has hs) h
  · exact Or.inl (nonemptyB_isNe hA)
  · exact Or.inr (any_eq_true hw2)

/-- I4 — W1a decisiveness: one refuting machine receipt refutes the claim;
    nothing downstream can rescue it (R1 halts the walk). Unbounded. -/
theorem I4_w1a_decisive (machine crit polCrit : Bool) (budget : Nat) (frs : Bool)
    (e : List Ev) (h : refutesIn (w1a e) = true) :
    (adjudicate machine crit polCrit budget frs e).value = .refuted := by
  have key : ∀ (m c p mo f : Bool) (d : Div) (hA sup al b supB w2r w2a w2 : Bool),
      hA = true →
      (adjudicateCore m c p mo f d false true hA sup al true b supB w2r w2a w2).value =
        .refuted := by
    intro m c p mo f d hA sup al b supB w2r w2a w2 ha
    cases d <;> revert m c p mo f hA sup al b supB w2r w2a w2 ha <;> decide
  have hA : nonemptyB (w1a e) = true := refutesIn_imp_has h
  have hAny : refutesIn e = true :=
    any_filter_imp_any (l := e) (p := fun x => x.1 == .w1a)
      (q := fun x => x.2 == .refutes) h
  have hEmpty : emptyB e = false := by
    cases e with
    | nil => simp [w1a, List.filter, nonemptyB, emptyB] at hA
    | cons _ _ => rfl
  unfold adjudicate
  rw [hEmpty, hAny, h]
  exact key machine crit polCrit (decide (1 ≤ budget)) frs (divergence e)
      (nonemptyB (w1a e)) (supportsIn (w1a e)) (allSupport (w1a e))
      (refutesIn (w1b e)) (supportsIn (w1b e))
      (refutesIn (w2plus e)) (allSupport (w2plus e))
      (e.any (fun x => x.1 == .w2)) hA

/-- I5 — doctrine cannot topple W1a: when every machine receipt supports,
    the value is neither REFUTED nor ESCALATED — whatever the doctrine,
    the deliberation flag, or the policy. Unbounded. -/
theorem I5_doctrine_cannot_topple (machine crit polCrit : Bool) (budget : Nat) (frs : Bool)
    (e : List Ev) (hs : supportsIn (w1a e) = true) (ha : allSupport (w1a e) = true) :
    (adjudicate machine crit polCrit budget frs e).value ≠ .refuted ∧
    (adjudicate machine crit polCrit budget frs e).value ≠ .escalated := by
  have key : ∀ (m c p mo f : Bool) (d : Div) (anyRef sup b supB w2r w2a w2 : Bool),
      sup = true →
      (adjudicateCore m c p mo f d false anyRef true sup true false b supB w2r w2a w2).value ≠
        .refuted ∧
      (adjudicateCore m c p mo f d false anyRef true sup true false b supB w2r w2a w2).value ≠
        .escalated := by
    intro m c p mo f d anyRef sup b supB w2r w2a w2 hs
    cases d <;> revert m c p mo f anyRef sup b supB w2r w2a w2 hs <;> decide
  have hA : nonemptyB (w1a e) = true := supportsIn_imp_has hs
  have hEmpty : emptyB e = false := by
    cases e with
    | nil => simp [w1a, List.filter, nonemptyB, emptyB] at hA
    | cons _ _ => rfl
  have href : refutesIn (w1a e) = false := allSupport_true_imp_refutes_false ha
  unfold adjudicate
  rw [hEmpty, hA, ha, href]
  exact key machine crit polCrit (decide (1 ≤ budget)) frs (divergence e)
      (refutesIn e) (supportsIn (w1a e)) (refutesIn (w1b e)) (supportsIn (w1b e))
      (refutesIn (w2plus e)) (allSupport (w2plus e)) (e.any (fun x => x.1 == .w2))
      hs

/-- I6 — escalation conditions: ESCALATED only when the doctrinal walk
    genuinely SPLITs on a critical-class claim, with NO machine evidence
    present and no W1b refutation pending. Unbounded. -/
theorem I6_escalated_conditions (machine crit polCrit : Bool) (budget : Nat) (frs : Bool)
    (e : List Ev) (h : (adjudicate machine crit polCrit budget frs e).value = .escalated) :
    divergence e = .split ∧ crit = true ∧ polCrit = true ∧
    w1a e = [] ∧ refutesIn (w1b e) = false := by
  have key : ∀ (m mo f : Bool) (c p : Bool) (d : Div)
      (emp anyRef hA sup al ref b supB w2r w2a w2 : Bool),
      (adjudicateCore m c p mo f d emp anyRef hA sup al ref b supB w2r w2a w2).value =
        .escalated →
      d = .split ∧ c = true ∧ p = true ∧ hA = false ∧ b = false := by
    intro m mo f c p d emp anyRef hA sup al ref b supB w2r w2a w2 he
    cases d <;> revert m mo f c p emp anyRef hA sup al ref b supB w2r w2a w2 he <;> decide
  obtain ⟨hd, hc, hp, hA, hb⟩ :=
    key machine (decide (1 ≤ budget)) frs crit polCrit (divergence e) (emptyB e)
      (refutesIn e) (nonemptyB (w1a e)) (supportsIn (w1a e)) (allSupport (w1a e)) (refutesIn (w1a e))
      (refutesIn (w1b e)) (supportsIn (w1b e))
      (refutesIn (w2plus e)) (allSupport (w2plus e))
      (e.any (fun x => x.1 == .w2)) h
  refine ⟨hd, hc, hp, ?_, hb⟩
  have hA' : nonemptyB (w1a e) = false := hA
  cases l : w1a e with
  | nil => rfl
  | cons _ _ =>
      simp [l, nonemptyB, emptyB] at hA' 

/-- I7 — split stays visible: the first-round-split flag (§4.4.3) is
    propagated to the output verbatim, never dropped by consensus. -/
theorem I7_split_stays_visible (machine crit polCrit : Bool) (budget : Nat) (frs : Bool)
    (e : List Ev) : (adjudicate machine crit polCrit budget frs e).splitNoted = frs := by
  have key : ∀ (m c p mo f : Bool) (d : Div)
      (emp anyRef hA sup al ref b supB w2r w2a w2 : Bool),
      (adjudicateCore m c p mo f d emp anyRef hA sup al ref b supB w2r w2a w2).splitNoted =
        f := by
    intro m c p mo f d emp anyRef hA sup al ref b supB w2r w2a w2
    cases d <;> revert m c p mo f emp anyRef hA sup al ref b supB w2r w2a w2 <;> decide
  unfold adjudicate
  exact key machine crit polCrit (decide (1 ≤ budget)) frs (divergence e)
    (emptyB e) (refutesIn e) (nonemptyB (w1a e)) (supportsIn (w1a e)) (allSupport (w1a e))
    (refutesIn (w1a e)) (refutesIn (w1b e)) (supportsIn (w1b e)) (refutesIn (w2plus e))
    (allSupport (w2plus e)) (e.any (fun x => x.1 == .w2))

/-- I10 — meta-claim budget honored (§6.1): emitted meta-claims are exactly
    depth-1 coverage claims, and only when the policy budget allows ≥1. -/
theorem I10_meta_budget (machine crit polCrit : Bool) (budget : Nat) (frs : Bool)
    (e : List Ev) :
    (adjudicate machine crit polCrit budget frs e).metaDepths = [] ∨
    ((adjudicate machine crit polCrit budget frs e).metaDepths = [1] ∧ 1 ≤ budget) := by
  have key : ∀ (m c p f : Bool) (d : Div)
      (mo emp anyRef hA sup al ref b supB w2r w2a w2 : Bool),
      (adjudicateCore m c p mo f d emp anyRef hA sup al ref b supB w2r w2a w2).metaDepths =
        [] ∨
      ((adjudicateCore m c p mo f d emp anyRef hA sup al ref b supB w2r w2a w2).metaDepths =
         [1] ∧ mo = true) := by
    intro m c p f d mo emp anyRef hA sup al ref b supB w2r w2a w2
    cases d <;> revert m c p f mo emp anyRef hA sup al ref b supB w2r w2a w2 <;> decide
  obtain (h | ⟨h, hmo⟩) :=
    key machine crit polCrit frs (divergence e) (decide (1 ≤ budget)) (emptyB e)
      (refutesIn e) (nonemptyB (w1a e)) (supportsIn (w1a e)) (allSupport (w1a e)) (refutesIn (w1a e))
      (refutesIn (w1b e)) (supportsIn (w1b e))
      (refutesIn (w2plus e)) (allSupport (w2plus e))
      (e.any (fun x => x.1 == .w2))
  · exact Or.inl h
  · exact Or.inr ⟨h, by simpa using hmo⟩

/-! ## Cross-model coherence: divergence never invents a split from silence -/

/-- A claim with no doctrinal evidence diverges unanimously — the R3/R4
    split-guards can only fire on real disagreement (any length). -/
theorem divergence_unanimous_without_doctrine (e : List Ev)
    (h : w2plus e = []) : divergence e = .unanimous := by
  simp [divergence, h]

end Ladder
