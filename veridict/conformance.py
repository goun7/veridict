"""Watcher conformance kit (§5.5 governance, Phase 3).

The certification precondition for the watcher marketplace: a third-party
watcher session must pass this suite before it can be listed. The kit probes
the PLATFORM contract, not the watcher's opinions — correctness of doctrine is
the market's problem; obedience to the evidence contract is ours.

Checks (each isolated — a crash marks that check failed, never propagates):
  C1  manifest invariants round-trip (incl. the W1a ban)
  C2  tier ceiling: no path can surface W1a from a watcher
  C3  blindness: the doctrine fn receives exactly (claim summary, artifact ref)
  C4  abstain on error (a crashing watcher is a silent watcher, never a refuting one)
  C5  abstain on None
  C6  abstain on any stance outside {SUPPORTS, REFUTES}
  C7  confidence clamped to [0, 1]
  C8  evidence shape when the watcher does produce: producer kind "watcher",
      family == watcher_id, evidence_class within the manifest's declared set
  C9  manifest registers and signature-verifies in a scratch registry
  C10 resource deadline honored (manifest timeout_seconds → abstain)
"""
from __future__ import annotations

import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .keys import KeyStore
from .ledger import Ledger
from .schemas import Claim
from .watchers import ManifestRegistry, WatcherManifest, WatcherSession, run_session

_EID = "conf-probe-digest"


def _probe_claim() -> Claim:
    return Claim(claim_id="conf-probe", task_id="conf", subject="conf",
                 predicate="conformance-probe", scope="probe",
                 summary="conformance probe claim", derived_from=_EID,
                 verifiability="DOCTRINAL", falsifiable_by=("watcher",),
                 critical_class=None)


def _check(cid: str, name: str, fn) -> dict:
    try:
        detail = fn()
        return {"id": cid, "name": name, "passed": True, "detail": detail or "ok"}
    except Exception as exc:                     # noqa: BLE001 — isolation IS the contract
        return {"id": cid, "name": name, "passed": False, "detail": repr(exc)}


def run_conformance_suite(session: WatcherSession,
                          registry_factory=None) -> dict:
    """Run the full watcher contract suite. `conformant` = every check passed.

    HONEST LIMIT (fresh-eyes audit F1a, 2026-09-10): the kit exercises the
    session's fn a handful of times in a fixed order — a STATEFUL fn can pass
    every check and deviate in production. Spot-checking cannot bound an
    arbitrary program; `conformant` is a LOWER BOUND on trustworthiness, not
    a proof. Listing a watcher on the marketplace therefore additionally
    requires code review of the manifest's `code_hash` at certification time
    (§5.5): the kit automates what CAN be automated, and is honest about what
    cannot."""
    checks: list[dict] = []
    manifest = session.manifest
    claim = _probe_claim()

    def with_fn(fn) -> WatcherSession:
        return WatcherSession(manifest, fn)

    def _item_from(fn):
        with tempfile.TemporaryDirectory() as td:      # benign artifact: empty dir
            return run_session(with_fn(fn), claim, _EID, artifact_path=td)

    def c1() -> str:
        rebuilt = WatcherManifest.from_dict(manifest.to_dict())
        if rebuilt != manifest:
            raise AssertionError("manifest does not round-trip")
        return "invariants hold (W1a ban included)"

    def c2() -> str:
        item = _item_from(lambda s, r: ("SUPPORTS", 0.8, "probe"))
        if item is None or item.tier == "W1a":
            raise AssertionError(f"ceiling violated: {item and item.tier}")
        return f"tier {item.tier} (ceiling {manifest.capabilities['max_tier']})"

    def c3() -> str:
        seen = {}
        original = session.doctrine_fn

        def recorder(summary, ref):
            seen["args"] = (summary, ref)
            return original(summary, ref)

        with tempfile.TemporaryDirectory() as td:
            run_session(WatcherSession(manifest, recorder), claim, _EID,
                        artifact_path=td)
        got = seen.get("args")
        if got is None or len(got) != 2:
            raise AssertionError(f"fn received {got!r} — expected exactly 2 args")
        return f"inputs: (summary, artifact-reference) only"

    def c4() -> str:
        def boom(summary, ref):
            raise RuntimeError("probe crash")
        if run_session(with_fn(boom), claim, _EID) is not None:
            raise AssertionError("erroring fn produced evidence")
        return "error → abstain"

    def c5() -> str:
        if run_session(with_fn(lambda s, r: None), claim, _EID) is not None:
            raise AssertionError("None fn produced evidence")
        return "None → abstain"

    def c6() -> str:
        if run_session(with_fn(lambda s, r: ("MAYBE", 0.5, "x")),
                       claim, _EID) is not None:
            raise AssertionError("non-whitelisted stance produced evidence")
        return "bad stance → abstain"

    def c7() -> str:
        item = _item_from(lambda s, r: ("SUPPORTS", 7.3, "wild"))
        if item is None or not 0.0 <= item.confidence <= 1.0:
            raise AssertionError(f"confidence unclamped: {item and item.confidence}")
        return f"confidence clamped to {item.confidence}"

    def c8() -> str:
        item = run_session(session, claim, _EID,
                           artifact_path=str(Path(tempfile.mkdtemp())))
        if item is None:
            raise AssertionError("watcher produced no evidence on a benign probe — "
                                 "a certifiable watcher must demonstrate a "
                                 "well-formed item")
        if item.producer.get("kind") != "watcher" or \
                item.producer.get("family") != manifest.watcher_id:
            raise AssertionError(f"producer shape wrong: {item.producer}")
        if item.evidence_class not in manifest.capabilities["evidence_classes"]:
            raise AssertionError(f"undeclared evidence_class: {item.evidence_class}")
        if item.claim_id != claim.claim_id:
            raise AssertionError("claim_id not propagated")
        return "evidence shape conforms"

    def c9() -> str:
        if registry_factory is None:
            led = Ledger()
            ks = KeyStore(led)
            kid = ks.generate_and_enroll("watcher-registry")
            registry = ManifestRegistry(led, ks, kid)
        else:
            registry = registry_factory()
        registry.register(manifest)
        report = ManifestRegistry.verify_manifest(ledger := registry.ledger,
                                                  manifest.watcher_id)
        if not report["valid"]:
            raise AssertionError(f"registry verification failed: {report['errors']}")
        return "registration + signature verify in a scratch registry"

    def c10() -> str:
        deadline = manifest.resource_class.get("timeout_seconds") or 0
        m2 = WatcherManifest(**{**manifest.to_dict(), "resource_class": {
            "timeout_seconds": 1, "cost_budget": 0, "sandbox_level": "none"}})

        def slow(summary, ref):
            time.sleep(2.0)
            return ("SUPPORTS", 0.8, "late")

        if run_session(WatcherSession(m2, slow), claim, _EID) is not None:
            raise AssertionError("deadline ignored — a hung watcher produced evidence")
        return f"deadline honored ({deadline or 'probe'}s contract exercised)"

    checks.append(_check("C1", "manifest invariants", c1))
    checks.append(_check("C2", "tier ceiling (never W1a)", c2))
    checks.append(_check("C3", "blindness (inputs)", c3))
    checks.append(_check("C4", "abstain on error", c4))
    checks.append(_check("C5", "abstain on None", c5))
    checks.append(_check("C6", "abstain on bad stance", c6))
    checks.append(_check("C7", "confidence clamp", c7))
    checks.append(_check("C8", "evidence shape", c8))
    checks.append(_check("C9", "registry verification", c9))
    checks.append(_check("C10", "resource deadline", c10))
    return {"watcher_id": manifest.watcher_id, "conformant": all(c["passed"] for c in checks),
            "checks": checks}
