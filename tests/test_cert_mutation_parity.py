"""Certificate MUTATION differential: valid certificates are mutated one
field at a time, and the reference verifier (veridict.certificate) must
agree with the spec-only verifier (examples/spec_verifier.py) on EVERY
mutation's validity — same verdict, not just both-nonzero. The tamper soak
covers the ledger chain; this covers the §11.3 certificate surface, where
a lying-but-well-formed certificate is exactly the attack.

Also pinned: every mutation that succeeds must FAIL verification (a
mutation that keeps the certificate valid would be a break of §11).
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples"))

from examples.spec_verifier import verify_certificate as spec_verify
from veridict.certificate import verify_certificate as ref_verify


def _issue_ledger_cert(tmp_path):
    from veridict.certificate import CertificateIssuer
    from veridict.claim_extractor import ClaimExtractor
    from veridict.jury import Opinion, ScriptedProvider
    from veridict.keys import KeyStore
    from veridict.ladder import adjudicate
    from veridict.ledger import Ledger
    from veridict.policy import PolicyDeclaration, Thresholds
    from veridict.schemas import ActorRef, EvidenceItem, TaskManifest
    from veridict.utils import sha256_hex

    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("mut")
    pol = PolicyDeclaration(policy_id="mut", mode="GATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    task = TaskManifest(task_id="mut-1", artifact_path="/x",
                        actor_identity="ai-dev",
                        intent_lines=("MACHINE: add computes the sum of two numbers",),
                        criticality=(), has_existing_tests=True, pytest_args=())
    claim = ClaimExtractor().extract(task, "digest-mut")[0]
    led.append("claim.registered", ActorRef(kind="system", identity="c", version="1"),
               claim.to_dict())
    it = EvidenceItem(
        evidence_id=sha256_hex("mut-item")[:24], claim_id=claim.claim_id,
        evidence_class="JURY_OPINION", tier="W2",
        producer={"kind": "jury", "identity": "j1", "version": "1", "family": "f1"},
        artifact_ref="digest-mut",
        reproducibility={"deterministic": False, "rerun_recipe": None},
        stance="SUPPORTS", confidence=0.9, rationale="ok")
    led.append("evidence.recorded",
               ActorRef(kind="jury", identity="j1", version="1"), it.to_dict())
    adj = adjudicate(claim, [it], pol)
    cert = CertificateIssuer(led, ks, kid).issue(
        task=task, artifact_digest="digest-mut", policy=pol, claims=[claim],
        adjudications=[adj], evidence_by_claim={claim.claim_id: [it]},
        jury_families=["f1"], disclosure_level="REDACTED",
        scope_limits=["claim coverage is heuristic, not exhaustive"])
    lp = str(tmp_path / "led.jsonl")
    cp = str(tmp_path / "cert.json")
    led.save(lp)
    json.dump(cert, open(cp, "w"))
    assert ref_verify(lp, cp)["valid"] and spec_verify(lp, cp)["valid"]
    return led, cert, lp, cp


def _mutations(cert):
    """(name, mutate_fn) pairs — one field per mutation."""
    out = []

    def top(field, value=None, drop=False):
        def fn(c):
            if drop:
                c.pop(field, None)
            else:
                c[field] = value
        return fn

    out.append(("cert_id-flip", top("cert_id", "ff" * 12)))
    out.append(("cert_id-drop", top("cert_id", drop=True)))
    out.append(("score-inflate", top("score", 0.42)))
    out.append(("score-zeroed", top("score", 0.0)))
    out.append(("risk-level-flip", top("risk_level", "critical")))
    out.append(("policy-mode-flip", top("policy_mode", "WATCH")))
    out.append(("disclosure-flip", top("disclosure_level", "FULL")))
    out.append(("schema-flip", top("schema_version", "9.9.9")))
    out.append(("claims-verdict-flip",
                top("claims", [{"claim_id": "0" * 24, "verdict_value": "VERIFIED"}])))
    out.append(("scope-limits-honesty-drop",
                top("scope_limits", ["some other limit"])))
    out.append(("anchor-chain-flip", top("ledger_anchor",
                                         {"checkpoint_seq": 0, "chain_hash": "0" * 64})))
    out.append(("anchor-drop", top("ledger_anchor", drop=True)))

    def sig_flip(c):
        # Guarantee a REAL flip: if the signature's first base64 char is
        # already 'A', the classic "A" + rest mutation is a no-op and the
        # certificate legitimately stays valid (Ed25519's first byte is
        # random, so this happens ~1/64 runs — a CI flake by construction).
        cur = c["signatures"][0]["sig_b64"]
        c["signatures"][0]["sig_b64"] = ("B" if cur[0] == "A" else "A") + cur[1:]
    out.append(("signature-flip", sig_flip))

    def sig_drop(c):
        c["signatures"] = []
    out.append(("signature-array-empty", sig_drop))

    def sig_drop_field(c):
        c.pop("signatures")
    out.append(("signature-array-missing", sig_drop_field))

    def extra_field(c):
        c["injected_by_attacker"] = True
    out.append(("unknown-field-injected", extra_field))
    return out


def test_reference_and_spec_agree_on_every_mutation(tmp_path):
    led, cert, lp, cp = _issue_ledger_cert(tmp_path)
    for name, mutate in _mutations(cert):
        c = copy.deepcopy(cert)
        mutate(c)
        mp = str(tmp_path / "mut.json")
        json.dump(c, open(mp, "w"))
        r = ref_verify(lp, mp)
        s = spec_verify(lp, mp)
        assert r["valid"] == s["valid"], (name, r["valid"], s["valid"],
                                          r.get("errors"), s.get("errors"))
        # fail-closed: a mutation that kept the certificate valid breaks §11
        assert not r["valid"], (name, "mutation kept the certificate VALID",
                                r.get("errors"))
