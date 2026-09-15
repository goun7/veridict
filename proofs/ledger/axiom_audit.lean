-- CI receipt: re-measures the axiom footprint of every chaining theorem on
-- each build (run via `lake env lean axiom_audit.lean`; not a lake target).
-- Expected output as of Lean v4.34.0: C1 axiom-free, C2-C6 [propext] only.
import Chain
#print axioms Chain.C1_empty_verifies
#print axioms Chain.C2_wellformed_accepted
#print axioms Chain.C3_prefix_closed
#print axioms Chain.C4_payload_edit_detected
#print axioms Chain.C5_remint_needs_collision
#print axioms Chain.C6_prev_rooted
