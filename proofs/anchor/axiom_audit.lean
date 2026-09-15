-- Kernel axiom audit for the anchor theorems (CI re-runs this; output is
-- pasted into the Anchor.lean header as the published receipt).
import Anchor

#print axioms Anchor.A0_fail_closed_parse
#print axioms Anchor.A1_binding_necessary
#print axioms Anchor.A2_soundness
#print axioms Anchor.A3_mint_accepted
#print axioms Anchor.A3b_mint_accepted_crypto_only
#print axioms Anchor.A4_sigs_cannot_rescue_binding
#print axioms Anchor.A5_tree_containment
#print axioms Anchor.A6_root_agreement
#print axioms Anchor.A7_uuid_embeds_leaf
