"""cli.py dal-kesen testleri — tum alt komutlar + yardimci fonksiyonlar.

Sadece NEW test dosyasi: mevcut test/production dosyalarina dokunulmaz.
Tum cagrilar subprocess'siz direkt fonksiyon cagrisi (cli.main(argv)).
Saf-bellek: ag yok (rekor httpx cagrisi sys.modules fake'i ile kesilir),
subprocess/socket yok; tmp_path + monkeypatch kullanilir.

Dal haritasi:
  D1  --help -> SystemExit(0) -> rc 0, usage yazisi
  D2  --version -> rc 0, surum yazisi
  D3  eksik/bilinmeyen alt komut -> _Parser.error -> rc 1 (argparse 2 degil)
  D4  gecersiz --mode/choices -> rc 1
  D5  audit basarili: rc 0, cert yazilir, blocked False, stub juri uyari
  D6  audit --mode GATE override -> cert policy_mode
  D7  audit --policy dosyasi -> policy modu yansir
  D8  audit gorev dosyasi yok -> OSError -> rc 1 stderr
  D9  audit --anchor tamga -> sidecar yazilir (seq/h/node_signed)
  D10 audit --anchor rekor (fake httpx 201) -> uuid/logIndex
  D11 audit --anchor rekor (fake httpx 500) -> rc 0, anchor hatasi raporu
  D12 audit --anchor rekor 500 + --anchor-required -> RuntimeError yukselir
  D13 audit --disclosure FULL -> cert disclosure_level FULL
  D14 audit --watcher gecersiz format -> SystemExit
  D15 audit --watcher gecerli (kayit + wiring) -> rc 0 + uyari
  D16 audit --watcher/manifest yok -> OSError -> rc 1
  D17 audit --watcher code_hash uyusmazligi -> SystemExit
  D18 verify positional standalone -> rc 0 valid
  D19 verify --cert --ledger -> rc 0
  D20 verify sertifika yok -> rc 1 "a certificate is required"
  D21 verify olmayan dosya -> OSError -> rc 1
  D22 verify receipt standalone + ledger -> rc 0
  D23 verify --anchor tamga sidecar rc 0; bozulmus sidecar rc 1
  D24 revoke rc 0; ardindan verify --ledger -> rc 1 (revoke gerekli)
  D25 revoke cert_id'siz JSON -> rc 1 "has no cert_id"
  D26 revoke ikinci kez rc 0 (SINIR: cift-revoke engellenmiyor)
  D27 receipt issue -> rc 0 default out; --out yazimi
  D28 receipt issue bos achievement -> ReceiptError -> rc 1
  D29 receipt list / --active-only dallari
  D30 receipt revoke --cert rc 0; --cert-id bilinmeyen -> rc 0 (idempotent
     SINIR: hic verilmemis id revoke'u sessizce gecer)
  D31 receipt revoke ne --cert ne --cert-id -> rc 1
  D32 receipt revoke sonrasi verify --ledger -> rc 1
  D33 anchor publish tamga rc 0; --anchor-ledger yok -> rc 1
  D34 anchor verify tamga rc 0; digest bozulmus -> rc 1
  D35 _anchor_verify bilinmeyen anchor_version -> rekor dogrulayici (red_Not)
  D36 export vsa rc 0; --out yazimi; uyumsuz ledger -> rc 1
  D37 export vsa --sign (registry init anahtar dosyasi) -> envelope rc 0
  D38 export spdx rc 0; --anchor-file -> ExternalRef
  D39 export spdx --sign -> rc 2 (DSSE yalniz VSA)
  D40 settle build rc 0 + --out; reconcile gecerli -> rc 0
  D41 settle reconcile kurcalanmis (accepted_claims) -> rc 1
  D42 settle reconcile dosya yok -> rc 1
  D43 registry init -> rc 0 anahtar dosyasi
  D44 registry register -> rc 0; list aktif; revoke -> revoked
  D45 registry register --key-file yok -> SystemExit
  D46 registry index -> rc 0 + out yazimi
  D47 dossier yok -> rc 1 "no dossier issued"
  D48 escalation senaryosu (juri SPLIT + policy kritik) -> audit rc 2 (blocked),
      dossier uretir; dossier --claim-id rc 0 markdown; --out yazimi
  D49 resolve gecerli -> rc 0; bilinmeyen karar rc 1; bilinmeyen dossier rc 1
  D50 index rc 0; --validate rc 0; --out yazimi; ledger yok rc 1
  D51 watch bos ledger (idle timeout) rc 0; dolu ledger max-batches 1 satir
  D52 watch --forever + max_batches 1 (idle 0.0 -> None) rc 0
  D53 quality-sheet rc 0 + jury_context (stub notu)
  D54 quality-sheet VERIDICT_JURY_URL varsa jury_context yok
  D55 _build_jury: cevresiz -> 2 stub + 2 uyari
  D56 _build_jury: URL -> 1 real 1 stub 1 uyari; URL2 -> 0 uyari
  D57 _build_jury: ACTOR_FAMILY bilinmeyen -> OK; stub aile -> ValueError
  D58 _load_watchers: None/[] -> ((), None)
  D59 _load_watchers: format hatasi/params: SystemExit/OSError/kanallar
  D60 _load_watchers: dis registry aktif degil -> SystemExit; aktif -> uyari
"""
from __future__ import annotations

import io
import json
import sys

import pytest

from veridict import anchor as anchor_mod
from veridict import cli
from veridict.keys import KeyStore
from veridict.jury import Jury, Opinion, ScriptedProvider
from veridict.ledger import Ledger


# ---------------------------------------------------------------- yardimlar

def _calistir(argv):
    """main'i calistir, (rc, stdout, stderr) dondur — subprocess YOK."""
    out, err = io.StringIO(), io.StringIO()
    eski_o, eski_e = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        rc = cli.main(argv)
    finally:
        sys.stdout, sys.stderr = eski_o, eski_e
    return rc, out.getvalue(), err.getvalue()


@pytest.fixture(autouse=True)
def _temiz_cevre(monkeypatch):
    for v in ("VERIDICT_JURY_URL", "VERIDICT_JURY_URL2", "VERIDICT_JURY_KEY2",
              "VERIDICT_JURY_MODEL2", "VERIDICT_ACTOR_FAMILY", "VERIDICT_HOME"):
        monkeypatch.delenv(v, raising=False)


def _gorev_yaz(tmp_path, intent=("MACHINE: x equals 1",), has_tests=False,
               task_id="cli-task"):
    art = tmp_path / "artifact"
    art.mkdir(exist_ok=True)
    (art / "mod.py").write_text("x = 1\n")
    gorev = {"task_id": task_id, "artifact_path": str(art),
             "actor_identity": "cli-actor", "intent_lines": list(intent),
             "criticality": [], "has_existing_tests": has_tests}
    tj = tmp_path / "task.json"
    tj.write_text(json.dumps(gorev))
    return tj


def _denetim(tmp_path, extra=(), task_id="cli-task"):
    """Bir audit kostur: rc 0 oldugunu varsayar, (ledger, cert, stdout) dondur."""
    tj = _gorev_yaz(tmp_path, task_id=task_id)
    led, cert = str(tmp_path / "ledger.jsonl"), str(tmp_path / "cert.json")
    rc, out, err = _calistir(["audit", "--task", str(tj), "--ledger", led,
                              "--cert-out", cert, *extra])
    assert rc == 0, f"audit beklenmedik basarisizlik: {err}"
    return led, cert, out


def _manifest_dict(watcher_id="w1", code_hash=None, subscribes=()):
    return {"watcher_id": watcher_id, "name": "Test Watcher",
            "version": "0.1.0",
            "producer": {"identity": "test-org", "maintainer": "test@org"},
            "capabilities": {"evidence_classes": ["STATIC_ANALYSIS"],
                             "max_tier": "W2",
                             "subscribes_to": list(subscribes)},
            "resource_class": {"timeout_seconds": 10, "cost_budget": 1,
                               "sandbox_level": "none"},
            "integrity": {"code_hash": code_hash, "update_policy": "review"}}


class _SahteRekorCevap:
    """httpx.Response taklidi — rekor publish aga cikmadan kesilir."""

    def __init__(self, status_code=201, entry=None, text="ok"):
        self.status_code = status_code
        self.text = text
        self._entry = entry

    def json(self):
        if self._entry is None:
            return {}
        return {"uuid-sahte-1": self._entry}


class _SahteHttpx:
    def __init__(self, cevap):
        self.cevap = cevap
        self.son_url = None
        self.son_body = None

    def post(self, url, json=None, timeout=None):
        self.son_url = url
        self.son_body = json
        return self.cevap


@pytest.fixture
def rekor_fake(monkeypatch):
    mod = _SahteHttpx(_SahteRekorCevap(201, {"body": "e30=", "integratedTime": 1,
                                             "logID": "log-1", "logIndex": 7}))
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


@pytest.fixture
def rekor_red(monkeypatch):
    mod = _SahteHttpx(_SahteRekorCevap(500, text="rekor unavailable"))
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


# ------------------------------------------------- parser ve yardim dallari

class TestParserDallari:
    """D1-D4: arguman parseri hata davranislari (argparse 2 degil 1)."""

    def test_help_rc0(self):
        rc, out, _ = _calistir(["--help"])
        assert rc == 0
        assert "usage: veridict" in out

    def test_version_rc0(self):
        rc, out, _ = _calistir(["--version"])
        assert rc == 0
        assert out.startswith("veridict ") and out.strip() != "veridict"

    @pytest.mark.parametrize("argv", [
        [],
        ["audit"],
        ["bilinmeyen-alt-komut"],
    ])
    def test_eksik_ya_da_bilinmeyen_komut_rc1(self, argv):
        rc, _, err = _calistir(argv)
        assert rc == 1
        assert "veridict: error:" in err

    @pytest.mark.parametrize("gecersiz", ["CERT", "geçersiz", "watch"])
    def test_gecersiz_mode_rc1(self, gecersiz):
        rc, _, err = _calistir(["audit", "--task", "t.json", "--ledger", "l.jsonl",
                                "--cert-out", "c.json", "--mode", gecersiz])
        assert rc == 1
        assert "veridict: error:" in err


# ------------------------------------------------------------- audit D5-D17

class TestAuditDallari:
    """D5-D17: audit alt komutunun basari/basarisiz/sinir dallari."""

    def test_basarili_audit(self, tmp_path):
        led, cert, out = _denetim(tmp_path)
        sonuc = json.loads(out)
        assert sonuc["blocked"] is False
        assert any("SCRIPTED STUB" in w for w in sonuc["warnings"])
        dis = json.loads((tmp_path / "cert.json").read_text())
        assert dis["cert_id"]
        assert dis["risk_level"] == "low"
        assert (tmp_path / "ledger.jsonl").exists()

    def test_mode_override_gate(self, tmp_path):
        led, cert, out = _denetim(tmp_path, extra=["--mode", "GATE"])
        dis = json.loads((tmp_path / "cert.json").read_text())
        assert dis["policy_mode"] == "GATE"

    def test_policy_dosyasi_mod_yansir(self, tmp_path):
        pol = {"policy_id": "test-pol-1", "mode": "WATCH", "criticality": [],
               "thresholds": {"min_jury_families": 2,
                              "divergence_tolerance": 0.3333333333333333,
                              "min_w1_coverage": 0.8,
                              "meta_claim_depth_budget": 2},
               "divergence_tolerance": 0.3333333333333333,
               "disclosure_level": "REDACTED", "deliberation_rounds": 1,
               "response_window_hours": 24}
        pyol = tmp_path / "policy.json"
        pyol.write_text(json.dumps(pol))
        _denetim(tmp_path, extra=["--policy", str(pyol)])
        dis = json.loads((tmp_path / "cert.json").read_text())
        assert dis["policy_mode"] == "WATCH"

    def test_gorev_dosyasi_yok_rc1(self, tmp_path):
        rc, _, err = _calistir(["audit", "--task", str(tmp_path / "yok.json"),
                                "--ledger", str(tmp_path / "l.jsonl"),
                                "--cert-out", str(tmp_path / "c.json")])
        assert rc == 1
        assert "veridict: error:" in err

    def test_anchor_tamga_sidecar_yazilir(self, tmp_path):
        anchor_ledger = tmp_path / "tamga.jsonl"
        led, cert, out = _denetim(
            tmp_path, extra=["--anchor", "tamga",
                             "--anchor-ledger", str(anchor_ledger)])
        sonuc = json.loads(out)
        assert sonuc["anchor"]["ledger"] == str(anchor_ledger)
        assert sonuc["anchor"]["seq"] >= 1
        assert sonuc["anchor"]["node_signed"] is False
        sidecar = tmp_path / "cert.json.anchor.json"
        assert sidecar.exists()
        sc = json.loads(sidecar.read_text())
        assert sc["anchor_version"] == "veridict-anchor-tamga-1"
        assert anchor_ledger.exists()

    def test_anchor_rekor_fake_basarili(self, tmp_path, rekor_fake):
        led, cert, out = _denetim(tmp_path, extra=["--anchor", "rekor"])
        sonuc = json.loads(out)
        assert sonuc["anchor"]["uuid"] == "uuid-sahte-1"
        assert sonuc["anchor"]["logIndex"] == 7
        assert rekor_fake.son_url.endswith("/api/v1/log/entries")
        assert rekor_fake.son_body["kind"] == "hashedrekord"
        sc = json.loads((tmp_path / "cert.json.anchor.json").read_text())
        assert sc["anchor_version"] == "veridict-anchor-1"

    def test_anchor_rekor_red_hata_raporu_rc0(self, tmp_path, rekor_red):
        led, cert, out = _denetim(tmp_path, extra=["--anchor", "rekor"])
        sonuc = json.loads(out)
        assert sonuc["anchor"]["error"] is not None
        assert "HTTP 500" in sonuc["anchor"]["error"]

    def test_anchor_rekor_red_required_runtime_error(self, tmp_path, rekor_red):
        tj = _gorev_yaz(tmp_path)
        with pytest.raises(RuntimeError, match="rekor rejected"):
            _calistir(["audit", "--task", str(tj),
                       "--ledger", str(tmp_path / "l.jsonl"),
                       "--cert-out", str(tmp_path / "c.json"),
                       "--anchor", "rekor", "--anchor-required"])

    def test_disclosure_full(self, tmp_path):
        _denetim(tmp_path, extra=["--disclosure", "FULL"])
        dis = json.loads((tmp_path / "cert.json").read_text())
        assert dis["disclosure_level"] == "FULL"

    @pytest.mark.parametrize("kotu_spec", ["sadece:iki-parca", "tek-parca"])
    def test_watcher_format_hatasi_systemexit(self, tmp_path, kotu_spec):
        tj = _gorev_yaz(tmp_path)
        with pytest.raises(SystemExit, match="expected manifest.json:module:fn"):
            _calistir(["audit", "--task", str(tj),
                       "--ledger", str(tmp_path / "l.jsonl"),
                       "--cert-out", str(tmp_path / "c.json"),
                       "--watcher", kotu_spec])

    def test_watcher_gecerli_kayit_ve_wiring(self, tmp_path):
        mf = tmp_path / "manifest.json"
        mf.write_text(json.dumps(_manifest_dict()))
        tj = _gorev_yaz(tmp_path)
        led, cert = str(tmp_path / "l.jsonl"), str(tmp_path / "c.json")
        rc, out, err = _calistir(["audit", "--task", str(tj), "--ledger", led,
                                  "--cert-out", cert,
                                  "--watcher", f"{mf}:math:acos"])
        assert rc == 0, err
        sonuc = json.loads(out)
        assert any("registered and wired" in w for w in sonuc["warnings"])
        # self-registration: audit ledger'inda watcher.registered kalmali
        giriler = [json.loads(l) for l in open(led) if l.strip()]
        assert any(g["entry_type"] == "watcher.registered" for g in giriler)

    def test_watcher_manifest_dosyasi_yok_rc1(self, tmp_path):
        tj = _gorev_yaz(tmp_path)
        rc, _, err = _calistir(["audit", "--task", str(tj),
                                "--ledger", str(tmp_path / "l.jsonl"),
                                "--cert-out", str(tmp_path / "c.json"),
                                "--watcher", f"{tmp_path / 'yok.json'}:math:acos"])
        assert rc == 1
        assert "veridict: error:" in err

    def test_watcher_code_hash_uyusmazligi_systemexit(self, tmp_path):
        mf = tmp_path / "manifest.json"
        mf.write_text(json.dumps(_manifest_dict(code_hash="0" * 64)))
        tj = _gorev_yaz(tmp_path)
        with pytest.raises(SystemExit, match="code_hash mismatch"):
            _calistir(["audit", "--task", str(tj),
                       "--ledger", str(tmp_path / "l.jsonl"),
                       "--cert-out", str(tmp_path / "c.json"),
                       "--watcher", f"{mf}:math:acos"])

    def test_watcher_cagrilamaz_fn_systemexit(self, tmp_path):
        mf = tmp_path / "manifest.json"
        mf.write_text(json.dumps(_manifest_dict()))
        tj = _gorev_yaz(tmp_path)
        with pytest.raises(SystemExit, match="is not callable"):
            _calistir(["audit", "--task", str(tj),
                       "--ledger", str(tmp_path / "l.jsonl"),
                       "--cert-out", str(tmp_path / "c.json"),
                       "--watcher", f"{mf}:math:pi"])


# ------------------------------------------------------- verify D18-D23

class TestVerifyDallari:
    """D18-D23: verify alt komutu (sertifika + receipt + anchor)."""

    def test_standalone_positional_rc0(self, tmp_path):
        led, cert, out = _denetim(tmp_path)
        rc, out, _ = _calistir(["verify", cert])
        assert rc == 0
        assert json.loads(out)["valid"] is True

    def test_ledger_ile_full_verify_rc0(self, tmp_path):
        led, cert, out = _denetim(tmp_path)
        rc, out, _ = _calistir(["verify", "--ledger", led, "--cert", cert])
        assert rc == 0
        rapor = json.loads(out)
        assert rapor["valid"] is True

    def test_sertifika_verilmedi_rc1(self, tmp_path):
        rc, _, err = _calistir(["verify"])
        assert rc == 1
        assert "a certificate is required" in err

    def test_olmayan_dosya_rc1(self, tmp_path):
        rc, _, err = _calistir(["verify", str(tmp_path / "yok.json")])
        assert rc == 1
        assert "veridict: error:" in err

    def test_receipt_standalone_ve_ledger_rc0(self, tmp_path):
        ws = tmp_path / "ws"
        rc, out, _ = _calistir(["receipt", "issue", "--workspace", str(ws),
                                "--achievement", "feat shipped",
                                "--actor", "agent-1"])
        assert rc == 0, out
        yol = json.loads(out)["receipt_path"]
        assert yol.endswith(".json") and __import__("os").path.exists(yol)
        rc, out, _ = _calistir(["verify", yol, "--ledger", str(ws / "ledger.jsonl")])
        assert rc == 0
        assert json.loads(out)["valid"] is True
        rc, out, _ = _calistir(["verify", yol])
        assert rc == 0
        assert json.loads(out)["valid"] is True

    def test_anchor_tamga_sidecar_rc0_ve_bozuk_rc1(self, tmp_path):
        anchor_ledger = tmp_path / "tamga.jsonl"
        led, cert, out = _denetim(
            tmp_path, extra=["--anchor", "tamga",
                             "--anchor-ledger", str(anchor_ledger)])
        sidecar = json.loads((tmp_path / "cert.json.anchor.json").read_text())
        rc, out, _ = _calistir(["verify", cert, "--anchor",
                                str(tmp_path / "sc.json")])
        (tmp_path / "sc.json").write_text(json.dumps(sidecar))
        rc, out, _ = _calistir(["verify", cert, "--anchor",
                                str(tmp_path / "sc.json")])
        assert rc == 0
        rapor = json.loads(out)
        assert rapor["anchor"]["valid"] is True
        # digest kurcalama: binding artik tutmuyor -> anchor gecersiz
        sidecar["digest"] = "ff" * 32
        (tmp_path / "sc2.json").write_text(json.dumps(sidecar))
        rc, out, _ = _calistir(["verify", cert, "--anchor",
                                str(tmp_path / "sc2.json")])
        assert rc == 1
        assert json.loads(out)["anchor"]["valid"] is False


# ------------------------------------------------------------ revoke D24-D26

class TestRevokeDallari:
    """D24-D26: revoke alt komutu ve sinir davranislar."""

    def test_revoke_ve_verify_redi(self, tmp_path):
        led, cert, out = _denetim(tmp_path)
        rc, out, _ = _calistir(["revoke", "--ledger", led, "--cert", cert,
                                "--reason", "test-revoke"])
        assert rc == 0
        sonuc = json.loads(out)
        assert sonuc["revoked"] is True
        assert sonuc["reason"] == "test-revoke"
        rc, out, _ = _calistir(["verify", "--ledger", led, "--cert", cert])
        assert rc == 1
        assert json.loads(out)["valid"] is False

    def test_cert_id_yoksa_rc1(self, tmp_path):
        bos = tmp_path / "bos.json"
        bos.write_text(json.dumps({"foo": 1}))
        led, cert, out = _denetim(tmp_path)
        rc, _, err = _calistir(["revoke", "--ledger", led, "--cert", str(bos)])
        assert rc == 1
        assert "has no cert_id" in err

    def test_cift_revoke_rc0(self, tmp_path):
        # SINIR/BUG-suphesi: ayni sertifika ikinci kez revoke edilince de
        # rc 0 doner — ledger'a ikinci bir certificate.revoked eklenir.
        led, cert, out = _denetim(tmp_path)
        _calistir(["revoke", "--ledger", led, "--cert", cert, "--reason", "ilk"])
        rc, out, _ = _calistir(["revoke", "--ledger", led, "--cert", cert,
                                "--reason", "ikinci"])
        assert rc == 0


# ----------------------------------------------------------- receipt D27-D32

class TestReceiptDallari:
    """D27-D32: receipt alt komutlari (issue/list/revoke/verify)."""

    def _issue(self, tmp_path, achievement="feat shipped", actor="agent-1"):
        ws = tmp_path / "ws"
        rc, out, _ = _calistir(["receipt", "issue", "--workspace", str(ws),
                                "--achievement", achievement, "--actor", actor,
                                "--evidence", "ev-1", "--evidence", "ev-2"])
        assert rc == 0, out
        return ws, json.loads(out)

    def test_issue_default_ve_out(self, tmp_path):
        ws, sonuc = self._issue(tmp_path)
        assert sonuc["issued"] is True
        assert sonuc["cert_id"]
        import os
        assert os.path.exists(sonuc["receipt_path"])
        rec = json.loads(open(sonuc["receipt_path"]).read())
        assert rec["certificate_type"] == "veridict-receipt-v1"
        # ozel --out
        ozel = tmp_path / "ozel" / "receipt.json"
        rc, out, _ = _calistir(["receipt", "issue", "--workspace", str(ws),
                                "--achievement", "baska feat", "--actor", "a2",
                                "--out", str(ozel)])
        assert rc == 0
        assert ozel.exists()

    def test_issue_bos_achievement_rc1(self, tmp_path):
        ws = tmp_path / "ws"
        rc, _, err = _calistir(["receipt", "issue", "--workspace", str(ws),
                                "--achievement", "", "--actor", "a1"])
        assert rc == 1
        assert "veridict: error:" in err

    def test_list_ve_active_only(self, tmp_path):
        ws, _ = self._issue(tmp_path, achievement="feat a")
        self._issue_path = None
        rc, out, _ = _calistir(["receipt", "list", "--workspace", str(ws)])
        assert rc == 0
        sonuc = json.loads(out)
        assert sonuc["count"] == 1
        assert any(1 <= s["seq"] for s in sonuc["receipts"])
        _calistir(["receipt", "issue", "--workspace", str(ws),
                   "--achievement", "feat b", "--actor", "a3"])
        rc, out, _ = _calistir(["receipt", "list", "--workspace", str(ws),
                                "--active-only"])
        assert json.loads(out)["count"] == 2

    def test_revoke_yollari(self, tmp_path):
        ws, sonuc = self._issue(tmp_path)
        yol = sonuc["receipt_path"]
        # ne --cert ne --cert-id -> rc 1
        rc, _, err = _calistir(["receipt", "revoke", "--workspace", str(ws)])
        assert rc == 1
        assert "give the receipt" in err
        # --cert-id ile bilinmeyen id (DUZELTILDI VERIDICT-REC-3): revoke_receipt
        # artik 'receipt.issued'-zorunludur — var-olmayan-makam-revoke'u rc 1.
        rc, _, err = _calistir(["receipt", "revoke", "--workspace", str(ws),
                                "--cert-id", "boyle-bir-id-yok"])
        assert rc == 1
        assert "never" in err
        # gecerli revoke --cert
        rc, out, _ = _calistir(["receipt", "revoke", "--workspace", str(ws),
                                "--cert", yol, "--reason", "tekrarlandi"])
        assert rc == 0
        assert json.loads(out)["revoked"] is True

    def test_revoke_sonrasi_verify_ledger_rc1(self, tmp_path):
        ws, sonuc = self._issue(tmp_path)
        _calistir(["receipt", "revoke", "--workspace", str(ws),
                   "--cert", sonuc["receipt_path"]])
        rc, out, _ = _calistir(["verify", sonuc["receipt_path"],
                                "--ledger", str(ws / "ledger.jsonl")])
        assert rc == 1
        assert json.loads(out)["valid"] is False
        # standalone hala gecerli: dosya imzasi bozulmadi
        rc, out, _ = _calistir(["verify", sonuc["receipt_path"]])
        assert rc == 0


# ----------------------------------------------------------- anchor D33-D35

class TestAnchorDallari:
    """D33-D35: anchor alt komutu (publish/verify) + _anchor_verify dispatch."""

    def _hazirlik(self, tmp_path):
        led, cert, out = _denetim(tmp_path)
        return led, json.loads((tmp_path / "cert.json").read_text())

    def test_publish_tamga_rc0(self, tmp_path):
        led, cert = self._hazirlik(tmp_path)
        anch = tmp_path / "anchor-ledger.jsonl"
        rc, out, _ = _calistir(["anchor", "publish", "--transport", "tamga",
                                "--ledger", led, "--cert",
                                str(tmp_path / "cert.json"),
                                "--anchor-ledger", str(anch)])
        assert rc == 0
        sc = json.loads(out)
        assert sc["anchor_version"] == "veridict-anchor-tamga-1"
        assert sc["tamga"]["seq"] >= 1
        assert anch.exists()

    def test_publish_tamga_ledger_gerekli_rc1(self, tmp_path):
        led, cert = self._hazirlik(tmp_path)
        rc, _, err = _calistir(["anchor", "publish", "--transport", "tamga",
                                "--ledger", led, "--cert",
                                str(tmp_path / "cert.json")])
        assert rc == 1
        assert "requires --anchor-ledger" in err

    def test_verify_tamga_rc0_ve_bezuk_rc1(self, tmp_path):
        led, cert = self._hazirlik(tmp_path)
        anch = tmp_path / "anchor-ledger.jsonl"
        sc_path = tmp_path / "sc.json"
        _calistir(["anchor", "publish", "--transport", "tamga", "--ledger", led,
                   "--cert", str(tmp_path / "cert.json"),
                   "--anchor-ledger", str(anch), "--out", str(sc_path)])
        rc, out, _ = _calistir(["anchor", "verify", "--ledger", led,
                                "--cert", str(tmp_path / "cert.json"),
                                "--anchor", str(sc_path)])
        assert rc == 0
        assert json.loads(out)["valid"] is True
        # digest kurcalama
        sc = json.loads(sc_path.read_text())
        sc["digest"] = "ab" * 32
        (tmp_path / "sc-bozuk.json").write_text(json.dumps(sc))
        rc, out, _ = _calistir(["anchor", "verify", "--ledger", led,
                                "--cert", str(tmp_path / "cert.json"),
                                "--anchor", str(tmp_path / "sc-bozuk.json")])
        assert rc == 1
        assert json.loads(out)["valid"] is False

    def test_anchor_verify_bilinmeyen_versiyon_rekor_duser(self, tmp_path):
        led, cert = self._hazirlik(tmp_path)
        # docstring "unknown version is a refusal, not a fallback" der; kod
        # bilinmeyen versiyonu rekor dogrulayicisina gonderur. Sonuc gecersiz
        # (rekor semantiklerinde kanit yok) ama davranis bir fallback'tir.
        sahte = {"anchor_version": "veridict-anchor-999", "rekor": {}}
        rc, out, _ = _calistir(["anchor", "verify", "--ledger", led,
                                "--cert", str(tmp_path / "cert.json"),
                                "--anchor", str(tmp_path / "sc.json")])
        (tmp_path / "sc.json").write_text(json.dumps(sahte))
        rc, out, _ = _calistir(["anchor", "verify", "--ledger", led,
                                "--cert", str(tmp_path / "cert.json"),
                                "--anchor", str(tmp_path / "sc.json")])
        assert rc == 1
        assert json.loads(out)["valid"] is False
        # birim seviyesinde dispatch
        sonuc = cli._anchor_verify(sahte, cert)
        assert sonuc["valid"] is False
        assert sonuc["errors"]

    def test_anchor_verify_tamga_dispatch(self, tmp_path):
        # _anchor_verify tamga versiyonunu tamga dogrulayicisina gonderir
        led, cert = self._hazirlik(tmp_path)
        anch = tmp_path / "anchor-ledger.jsonl"
        _calistir(["anchor", "publish", "--transport", "tamga", "--ledger", led,
                   "--cert", str(tmp_path / "cert.json"),
                   "--anchor-ledger", str(anch), "--out",
                   str(tmp_path / "sc.json")])
        sc = json.loads((tmp_path / "sc.json").read_text())
        sonuc = cli._anchor_verify(sc, cert)
        assert sonuc["valid"] is True


# ----------------------------------------------------------- export D36-D39

class TestExportDallari:
    """D36-D39: export alt komutu (vsa/spdx/sign)."""

    def test_export_vsa_rc0(self, tmp_path):
        led, cert, out = _denetim(tmp_path)
        rc, out, _ = _calistir(["export", "--format", "vsa", "--cert", cert,
                                "--ledger", led])
        assert rc == 0
        doc = json.loads(out)
        assert "predicateType" in doc or "predicate" in doc

    def test_export_vsa_out_ve_uyumsuz_ledger(self, tmp_path):
        led, cert, out = _denetim(tmp_path)
        hedef = tmp_path / "stmt.json"
        rc, _, _ = _calistir(["export", "--format", "vsa", "--cert", cert,
                              "--ledger", led, "--out", str(hedef)])
        assert rc == 0 and hedef.exists()
        # issuance kaydi tasiyan baska ledger -> ValueError -> rc 1
        bos = tmp_path / "baska.jsonl"
        bos.write_text("")
        rc, _, err = _calistir(["export", "--format", "vsa", "--cert", cert,
                                "--ledger", str(bos)])
        assert rc == 1
        assert "certificate.issued" in err

    def test_export_vsa_sign_registry_anahtari(self, tmp_path):
        led, cert, out = _denetim(tmp_path)
        reg = tmp_path / "registry.jsonl"
        anahtar = tmp_path / "registry.jsonl.key.json"
        rc, _, err = _calistir(["registry", "init", "--registry", str(reg),
                                "--key-out", str(anahtar)])
        assert rc == 0 and anahtar.exists()
        anahtar_icerigi = json.loads(anahtar.read_text())
        assert anahtar_icerigi["private_pem"].startswith("-----BEGIN")
        rc, out, _ = _calistir(["export", "--format", "vsa", "--cert", cert,
                                "--ledger", led, "--sign", str(anahtar)])
        assert rc == 0
        doc = json.loads(out)
        assert "envelope" in doc
        assert doc["envelope"]["payloadType"]
        assert doc["envelope"]["signatures"]

    def test_export_spdx_rc0(self, tmp_path):
        led, cert, out = _denetim(tmp_path)
        rc, out, _ = _calistir(["export", "--format", "spdx", "--cert", cert,
                                "--ledger", led])
        assert rc == 0
        doc = json.loads(out)
        assert "@context" in doc
        assert len(doc["@graph"]) >= 1
        assert any("spdxId" in eleman for eleman in doc["@graph"])

    def test_export_spdx_sign_rc2(self, tmp_path):
        led, cert, out = _denetim(tmp_path)
        anahtar = tmp_path / "anahtar.pem"
        anahtar.write_text("-----BEGIN PRIVATE KEY-----\nZ2IK\n-----END PRIVATE KEY-----\n")
        rc, _, err = _calistir(["export", "--format", "spdx", "--cert", cert,
                                "--ledger", led, "--sign", str(anahtar)])
        assert rc == 2
        assert "only wraps VSA statements" in err

    def test_export_spdx_anchor_file_externalref(self, tmp_path):
        led, cert, out = _denetim(tmp_path, extra=["--anchor", "tamga",
                                                   "--anchor-ledger",
                                                   str(tmp_path / "t.jsonl")])
        sc = json.loads((tmp_path / "cert.json.anchor.json").read_text())
        # to_spdx yalniz rekor sidecar'indan ExternalRef yaratir; ayni
        # baglamani tasiyan bir rekor-format sidecar uretip veriyoruz.
        cert_doc = json.loads((tmp_path / "cert.json").read_text())
        bound = anchor_mod.bound_fields(cert_doc)
        rekor_sc = {"anchor_version": anchor_mod.ANCHOR_TYPE,
                    "rekor": {"server": "https://rekor.sigstore.dev",
                              "uuid": "u" * 96,
                              "entry": {"body": "e30=", "integratedTime": 1,
                                        "logID": "l", "logIndex": 3}},
                    "bound": bound,
                    "digest": anchor_mod.anchor_digest(bound)}
        sc_yol = tmp_path / "rekor-sc.json"
        sc_yol.write_text(json.dumps(rekor_sc))
        rc, out, _ = _calistir(["export", "--format", "spdx", "--cert",
                                cert, "--ledger", led, "--anchor-file",
                                str(sc_yol)])
        assert rc == 0
        assert "/api/v1/log/entries/" in out
        # DALGA-6-F4 (DUZELTILDI): tamga-binding'i tasiyan GERCEK sidecar
        # eskiden ExternalRef'i sessizce-dusuruyordu (kanit-kaybı); artik
        # tamga-ledger-yolu-da-yansitilir.
        rc2, out2, _ = _calistir(["export", "--format", "spdx", "--cert",
                                  cert, "--ledger", led, "--anchor-file",
                                  str(tmp_path / "cert.json.anchor.json")])
        assert rc2 == 0
        assert "veridict:tamga:" in out2
        assert f"#seq={sc['tamga']['seq']}" in out2


# ----------------------------------------------------------- settle D40-D42

class TestSettleDallari:
    """D40-D42: settle alt komutu (build/reconcile)."""

    def _hazirlik(self, tmp_path):
        _, cert, _ = _denetim(tmp_path)
        return cert

    def test_build_rc0_ve_out(self, tmp_path):
        cert = self._hazirlik(tmp_path)
        hedef = tmp_path / "claim.json"
        rc, out, _ = _calistir(["settle", "--cert", cert, "--out", str(hedef)])
        assert rc == 0 and hedef.exists()
        doc = json.loads(out)
        cert_doc = json.loads((tmp_path / "cert.json").read_text())
        assert doc["cert_id"] == cert_doc["cert_id"]
        assert doc["accepted_claims"] == doc["total_claims"]
        assert doc["risk_level"] == "low"
        assert "claim_digest" in doc

    def test_reconcile_gecerli_rc0(self, tmp_path):
        cert = self._hazirlik(tmp_path)
        hedef = tmp_path / "claim.json"
        _calistir(["settle", "--cert", cert, "--out", str(hedef)])
        rc, out, _ = _calistir(["settle", "--cert", cert, "--claim", str(hedef)])
        assert rc == 0
        assert json.loads(out).get("valid") is True

    def test_reconcile_kurcalanmis_rc1(self, tmp_path):
        cert = self._hazirlik(tmp_path)
        hedef = tmp_path / "claim.json"
        _calistir(["settle", "--cert", cert, "--out", str(hedef)])
        doc = json.loads(hedef.read_text())
        doc["accepted_claims"] += 1     # ic tutarsizlik: digest artik tutmuyor
        hedef.write_text(json.dumps(doc))
        rc, _, err = _calistir(["settle", "--cert", cert, "--claim", str(hedef)])
        assert rc == 1

    def test_reconcile_dosya_yok_rc1(self, tmp_path):
        cert = self._hazirlik(tmp_path)
        rc, _, err = _calistir(["settle", "--cert", cert,
                                "--claim", str(tmp_path / "yok.json")])
        assert rc == 1
        assert "veridict: error:" in err


# --------------------------------------------------------- registry D43-D46

class TestRegistryDallari:
    """D43-D46: registry alt komutlari (init/register/revoke/list/index)."""

    def _init(self, tmp_path):
        reg = tmp_path / "registry.jsonl"
        anahtar = tmp_path / "anahtar.json"
        rc, out, err = _calistir(["registry", "init", "--registry", str(reg),
                                  "--key-out", str(anahtar)])
        assert rc == 0, err
        return reg, anahtar, json.loads(out)

    def _manifest_yol(self, tmp_path, watcher_id="w1"):
        mf = tmp_path / f"manifest-{watcher_id}.json"
        mf.write_text(json.dumps(_manifest_dict(watcher_id)))
        return mf

    def test_init_rc0(self, tmp_path):
        reg, anahtar, sonuc = self._init(tmp_path)
        assert sonuc["registry"] == str(reg)
        assert sonuc["key_id"]
        assert anahtar.exists()
        data = json.loads(anahtar.read_text())
        assert data["private_pem"].startswith("-----BEGIN")
        assert data["key_id"] == sonuc["key_id"]
        assert reg.exists()

    def test_bos_list_rc0(self, tmp_path):
        reg, anahtar, _ = self._init(tmp_path)
        rc, out, _ = _calistir(["registry", "list", "--registry", str(reg)])
        assert rc == 0
        assert out.strip() == ""

    def test_register_list_revoke_dongusu(self, tmp_path):
        reg, anahtar, _ = self._init(tmp_path)
        mf = self._manifest_yol(tmp_path)
        rc, out, err = _calistir(["registry", "register", "--registry", str(reg),
                                  "--manifest", str(mf), "--key-file", str(anahtar)])
        assert rc == 0, err
        assert json.loads(out)["registered"] == "w1"
        rc, out, _ = _calistir(["registry", "list", "--registry", str(reg)])
        assert rc == 0
        assert "w1" in out and "active" in out
        rc, out, _ = _calistir(["registry", "revoke", "--registry", str(reg),
                                "--watcher-id", "w1", "--reason", "eski",
                                "--key-file", str(anahtar)])
        assert rc == 0
        assert json.loads(out)["revoked"] == "w1"
        rc, out, _ = _calistir(["registry", "list", "--registry", str(reg)])
        assert "revoked" in out

    def test_register_anahtar_gerekli_systemexit(self, tmp_path):
        reg, anahtar, _ = self._init(tmp_path)
        mf = self._manifest_yol(tmp_path)
        with pytest.raises(SystemExit, match="--key-file required"):
            _calistir(["registry", "register", "--registry", str(reg),
                       "--manifest", str(mf)])

    def test_index_rc0_out(self, tmp_path):
        reg, anahtar, _ = self._init(tmp_path)
        mf = self._manifest_yol(tmp_path)
        _calistir(["registry", "register", "--registry", str(reg),
                   "--manifest", str(mf), "--key-file", str(anahtar)])
        hedef = tmp_path / "index.json"
        rc, out, _ = _calistir(["registry", "index", "--registry", str(reg),
                                "--out", str(hedef)])
        assert rc == 0 and hedef.exists()
        assert "w1" in out


# ----------------------------------------------- dossier/resolve D47-D49

class TestDossierResolveDallari:
    """D47-D49: dossier + resolve (escalation senaryosu ile)."""

    def _bolunmus_juri(self, monkeypatch):
        def _fake():
            juri = Jury([
                ScriptedProvider("aile-a", "kimlik-a", Opinion("SUPPORTS", 0.8, "destek")),
                ScriptedProvider("aile-b", "kimlik-b", Opinion("REFUTES", 0.9, "karsi"))])
            return juri, []
        monkeypatch.setattr(cli, "_build_jury", _fake)

    def _politika(self, tmp_path):
        pol = {"policy_id": "kritik-pol", "mode": "HYBRID",
               "criticality": ["sec"], "deliberation_rounds": 0,
               "thresholds": {"min_jury_families": 2,
                              "divergence_tolerance": 0.3333333333333333,
                              "min_w1_coverage": 0.8,
                              "meta_claim_depth_budget": 0},
               "divergence_tolerance": 0.3333333333333333,
               "disclosure_level": "REDACTED", "response_window_hours": 24}
        pyol = tmp_path / "policy.json"
        pyol.write_text(json.dumps(pol))
        return str(pyol)

    def test_dossier_yoksa_rc1(self, tmp_path):
        led, cert, out = _denetim(tmp_path)
        rc, _, err = _calistir(["dossier", "--ledger", led, "--claim-id", "yok-id"])
        assert rc == 1
        assert "no dossier issued" in err

    def test_escalasyon_dossier_ve_resolve(self, tmp_path, monkeypatch):
        self._bolunmus_juri(monkeypatch)
        pyol = self._politika(tmp_path)
        tj = _gorev_yaz(tmp_path, intent=("DOCTRINE(sec): module tolerates concurrent writers",))
        led, cert = str(tmp_path / "ledger.jsonl"), str(tmp_path / "cert.json")
        rc, out, err = _calistir(["audit", "--task", str(tj), "--ledger", led,
                                  "--cert-out", cert, "--policy", pyol])
        # R3 escalation policy katmaninda blocked olur -> audit rc 2
        assert rc == 2, err
        giriler = [json.loads(l) for l in open(led) if l.strip()]
        dossierler = [g for g in giriler if g["entry_type"] == "dossier.issued"]
        assert dossierler, "escalation bir dossier uretmeli (R3)"
        did = dossierler[0]["payload"]["dossier_id"]
        clid = dossierler[0]["payload"]["claim"]["claim_id"]
        # dossier --claim-id
        rc, out, _ = _calistir(["dossier", "--ledger", led, "--claim-id", clid])
        assert rc == 0
        assert clid in out or "dossier" in out.lower()
        # --out yazimi
        md = tmp_path / "dossier.md"
        rc, _, _ = _calistir(["dossier", "--ledger", led, "--claim-id", clid,
                              "--out", str(md)])
        assert rc == 0 and md.exists() and md.read_text() != ""
        # resolve gecerli
        rc, out, _ = _calistir(["resolve", "--ledger", led,
                                "--dossier-id", did, "--decision", "accept_with_risk",
                                "--decided-by", "alice", "--note", "kabul"])
        assert rc == 0
        assert "accept_with_risk" in out and "alice" in out
        giriler = [json.loads(l) for l in open(led) if l.strip()]
        assert any(g["entry_type"] == "escalation.resolved" for g in giriler)

    @pytest.mark.parametrize("karar, dossier_id, mesaj", [
        ("BOGUS", "herhangi", "unknown decision"),
        ("reject", "yok-byle-dossier", "unknown dossier_id"),
    ])
    def test_resolve_gecersiz_rc1(self, tmp_path, monkeypatch, karar,
                                  dossier_id, mesaj):
        self._bolunmus_juri(monkeypatch)
        pyol = self._politika(tmp_path)
        tj = _gorev_yaz(tmp_path, intent=("DOCTRINE(sec): module tolerates concurrent writers",))
        led, cert = str(tmp_path / "ledger.jsonl"), str(tmp_path / "cert.json")
        _calistir(["audit", "--task", str(tj), "--ledger", led,
                   "--cert-out", cert, "--policy", pyol])
        rc, _, err = _calistir(["resolve", "--ledger", led,
                                "--dossier-id", dossier_id, "--decision", karar,
                                "--decided-by", "bob"])
        assert rc == 1
        assert mesaj in err


# ------------------------------------------------------------- index D50

class TestIndexDallari:
    """D50: index alt komutu."""

    def test_index_rc0_ve_validate(self, tmp_path):
        led, cert, out = _denetim(tmp_path)
        rc, out, _ = _calistir(["index", "--ledger", led])
        assert rc == 0
        assert json.loads(out)["watchers"] is not None
        rc, out, _ = _calistir(["index", "--ledger", led, "--validate"])
        assert rc == 0
        assert json.loads(out)["valid"] is True
        hedef = tmp_path / "idx.json"
        rc, _, _ = _calistir(["index", "--ledger", led, "--out", str(hedef)])
        assert rc == 0 and hedef.exists()

    def test_index_ledger_yok_rc1(self, tmp_path):
        rc, _, err = _calistir(["index", "--ledger", str(tmp_path / "yok.jsonl")])
        assert rc == 1
        assert "veridict: error:" in err


# ------------------------------------------------------------- watch D51-D52

class TestWatchDallari:
    """D51-D52: watch (streaming) alt komutu — okuma-only gozlemci."""

    def test_bos_ledger_idle_timeout(self, tmp_path):
        bos = tmp_path / "watch.jsonl"
        bos.write_text("")
        rc, out, _ = _calistir(["watch", "--ledger", str(bos),
                                "--max-batches", "1",
                                "--idle-timeout", "0.2", "--poll-interval", "0.01"])
        assert rc == 0
        assert out.strip() == ""

    def test_dolu_ledger_tek_batch(self, tmp_path):
        led, cert, out = _denetim(tmp_path)
        rc, out, _ = _calistir(["watch", "--ledger", led, "--max-batches", "1",
                                "--idle-timeout", "1.0", "--poll-interval", "0.01"])
        assert rc == 0
        satirlar = [s for s in out.strip().splitlines() if s.strip()]
        assert len(satirlar) == 1
        gozlem = json.loads(satirlar[0])
        assert gozlem["kind"] and gozlem["seq_to"] >= gozlem["seq_from"]

    def test_forever_flagi_max_batches_ile_sonlanir(self, tmp_path):
        # --forever idle=0.0 -> None; yine max-batches ile sonlanir
        led, cert, out = _denetim(tmp_path)
        rc, out, _ = _calistir(["watch", "--ledger", led, "--forever",
                                "--max-batches", "1", "--poll-interval", "0.01"])
        assert rc == 0
        assert out.strip() != ""


# ------------------------------------------------------- quality-sheet D53-D54

class TestQualitySheetDallari:
    """D53-D54: quality-sheet alt komutu (canary)."""

    def _mini_corpus(self, tmp_path):
        art = tmp_path / "canary-artifact"
        art.mkdir(exist_ok=True)
        (art / "mod.py").write_text("def add(a, b):\n    return a + b\n")
        satir = {"id": "mini-1", "path": str(art), "defect_class": "temiz",
                 "ground_truth": "CLEAN",
                 "intent": ["MACHINE: add computes the sum of two numbers"],
                 "criticality": []}
        corpus = tmp_path / "corpus.jsonl"
        corpus.write_text(json.dumps(satir) + "\n")
        return str(corpus)

    def test_sheet_rc0_jury_context(self, tmp_path):
        cikti = tmp_path / "sheet.json"
        rc, out, _ = _calistir(["quality-sheet", "--corpus",
                                self._mini_corpus(tmp_path), "--out", str(cikti)])
        assert rc == 0
        assert cikti.exists()
        sheet = json.loads(cikti.read_text())
        assert sheet["per_class"]["temiz"]["total"] == 1
        assert sheet["caught_total"] == 0         # CLEAN case -> yakalanmaz
        assert "stub jury" in sheet["jury_context"]
        assert "temiz" in json.loads(out)

    def test_jury_env_varsa_kontekst_notu_yok(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VERIDICT_JURY_URL", "http://yerel:8847/v1")
        cikti = tmp_path / "sheet.json"
        rc, out, _ = _calistir(["quality-sheet", "--corpus",
                                self._mini_corpus(tmp_path), "--out", str(cikti)])
        assert rc == 0
        sheet = json.loads(cikti.read_text())
        assert "jury_context" not in sheet


# --------------------------------------------------- _build_jury D55-D57

class TestBuildJuryDallari:
    """D55-D57: _build_jury cevre degiskeni dallari (ag yok)."""

    def test_cevresiz_iki_stub_iki_uyari(self, monkeypatch):
        juri, uyari = cli._build_jury()
        aileler = [p.family for p in juri.providers]
        assert aileler == ["stub-1", "stub-2"]
        assert len(uyari) == 2
        assert all("SCRIPTED STUB" in u for u in uyari)

    def test_tek_url_bir_real_bir_stub(self, monkeypatch):
        monkeypatch.setenv("VERIDICT_JURY_URL", "http://yerel:8847/v1")
        juri, uyari = cli._build_jury()
        aileler = [p.family for p in juri.providers]
        assert aileler == ["openai-compat-1", "stub-1"]
        assert len(uyari) == 1

    def test_iki_url_sifir_uyari(self, monkeypatch):
        monkeypatch.setenv("VERIDICT_JURY_URL", "http://yerel:8847/v1")
        monkeypatch.setenv("VERIDICT_JURY_URL2", "http://yerel2:8847/v1")
        monkeypatch.setenv("VERIDICT_JURY_KEY2", "anahtar-2")
        monkeypatch.setenv("VERIDICT_JURY_MODEL2", "model-2")
        juri, uyari = cli._build_jury()
        aileler = [p.family for p in juri.providers]
        assert aileler == ["openai-compat-1", "openai-compat-2"]
        assert uyari == []
        ikinci = juri.providers[1]
        assert ikinci.identity == "http-2"

    def test_actor_family_bilinmeyen_ok(self, monkeypatch):
        monkeypatch.setenv("VERIDICT_ACTOR_FAMILY", "farkli-aile")
        juri, uyari = cli._build_jury()
        assert len(juri.providers) == 2

    def test_actor_family_stub_only_panelde_yok_sayilir(self, monkeypatch):
        """DALGA-6-F6 (DUZELTILDI): sadece stub saglayici varken actor_family
        eskiden §5.2 '>=2 providers' kosulunu-vurup-tüm-audit'i-ölduruyordu —
        stub-panelde-aile-anlamsiz: uyar-not-dus ve-None'a-dusulur."""
        monkeypatch.setenv("VERIDICT_ACTOR_FAMILY", "stub-1")
        juri, uyari = cli._build_jury()
        assert len(juri.providers) == 2   # stub-1 + stub-2, aile-filtresi-yok
        assert juri.excluded == []
        assert any("ignored" in u for u in uyari)


# ------------------------------------------------- _load_watchers D58-D60

class TestLoadWatchersDallari:
    """D58-D60: _load_watchers (spec cozumu + registry)."""

    def _altyapi(self):
        led = Ledger()
        ks = KeyStore(led)
        kid = ks.generate_and_enroll("test")
        return led, ks, kid

    def _manifest_yol(self, tmp_path, **kw):
        mf = tmp_path / "mf.json"
        mf.write_text(json.dumps(_manifest_dict(**kw)))
        return str(mf)

    @pytest.mark.parametrize("specs", [None, []])
    def test_bos_spec_bos_doner(self, specs):
        led, ks, kid = self._altyapi()
        uyari = []
        sessions, donen_ledger = cli._load_watchers(specs, led, ks, kid, uyari)
        assert sessions == () and sessions is not None
        assert donen_ledger is None
        assert uyari == []

    def test_format_hatasi_systemexit(self, tmp_path):
        led, ks, kid = self._altyapi()
        with pytest.raises(SystemExit, match="expected manifest.json:module:fn"):
            cli._load_watchers(["a:b"], led, ks, kid, [])

    def test_gecerli_spec_session_ve_uyari(self, tmp_path):
        led, ks, kid = self._altyapi()
        mf = self._manifest_yol(tmp_path)
        uyari = []
        sessions, donen = cli._load_watchers(
            [f"{mf}:math:acos"], led, ks, kid, uyari)
        assert len(sessions) == 1
        assert donen is led
        assert any("registered and wired" in u for u in uyari)
        # self-registration ledger'a yazilmali
        assert any(e["entry_type"] == "watcher.registered" for e in led.entries)

    def test_manifest_dosyasi_yok_oserror(self, tmp_path):
        led, ks, kid = self._altyapi()
        with pytest.raises(OSError):
            cli._load_watchers([f"{tmp_path / 'yok.json'}:math:acos"],
                               led, ks, kid, [])

    def test_code_hash_uyusmazligi_systemexit(self, tmp_path):
        led, ks, kid = self._altyapi()
        mf = self._manifest_yol(tmp_path, code_hash="f" * 64)
        with pytest.raises(SystemExit, match="code_hash mismatch"):
            cli._load_watchers([f"{mf}:math:acos"], led, ks, kid, [])

    def test_cagrilamaz_fn_systemexit(self, tmp_path):
        led, ks, kid = self._altyapi()
        mf = self._manifest_yol(tmp_path)
        with pytest.raises(SystemExit, match="is not callable"):
            cli._load_watchers([f"{mf}:math:pi"], led, ks, kid, [])

    def test_dis_registry_pasif_degil_systemexit(self, tmp_path):
        # watcher hic kayitli degil -> "unknown" -> SystemExit
        reg = Ledger()
        reg.save(str(tmp_path / "reg.jsonl"))
        led, ks, kid = self._altyapi()
        mf = self._manifest_yol(tmp_path)
        with pytest.raises(SystemExit, match="not registered/active"):
            cli._load_watchers([f"{mf}:math:acos"], led, ks, kid, [],
                               registry_ledger=reg)

    def test_dis_registry_aktif_uyari_verir(self, tmp_path):
        # once registry ledgerinda watcher'i kaydet, sonra audit tarafinda
        # dis registry gec: self-registration YOK, uyari var
        reg = Ledger()
        rks = KeyStore(reg)
        rkid = rks.generate_and_enroll("registry-owner")
        from veridict.watchers import ManifestRegistry, WatcherManifest
        manifest = WatcherManifest.from_dict(_manifest_dict())
        reg_led = ManifestRegistry(reg, rks, rkid)
        reg_led.register(manifest)
        reg.save(str(tmp_path / "reg.jsonl"))
        led, ks, kid = self._altyapi()
        mf = self._manifest_yol(tmp_path)
        uyari = []
        sessions, _ = cli._load_watchers(
            [f"{mf}:math:acos"], led, ks, kid, uyari, registry_ledger=reg)
        assert len(sessions) == 1
        assert any("active in external registry" in u for u in uyari)
        # self-register edilmemeli: audit ledger'inda watcher.registered yok
        assert not any(e["entry_type"] == "watcher.registered"
                       for e in led.entries)
