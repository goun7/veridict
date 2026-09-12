#!/usr/bin/env python3
"""pugio_watch_receiver — K0 §6 watch-feed alıcısı (K3 köprüsü, Veridict tarafı).

PUGIO metering katmanının karar-denetim akışını (watch_manifest →
watch_event* → watch_close) alır ve **yalnız sha256** ile yeniden-hash'ler:

    entry_sha = SHA256(prev_entry_sha|seq|ts|agent|host|rule_id|decision)

Veridict'in "AI'ı AI'la denetleme" doktrinine giriş-noktası: PUGIO'nun
politika-kararları buradan beslenip makine-doğrulanabilir claim'lere
dönüştürülebilir (kanıt: watch_head). İlk-adım ilkesi (K0 §7): Veridict
çekirdeğine dokunmaz, bağımlılık eklemez; pür stdlib.

Kullanım:
    python scripts/pugio_watch_receiver.py akis.jsonl    # doğrula (exit 0/1)
    python scripts/pugio_watch_receiver.py --selftest    # temiz→PASS, bozuk→RED

Fail-loud: tek satır bile RED ise exit 1 (sessiz-geçiş yok — ortak doktrin).

BİLİNEN SINIR (v1, dürüstlük): manifest'in kendi DEĞERLERİ (bundle_head,
bundle_merkle_root, source, watcher_id) zincire bağlı DEĞİLDİR — yalnız
alan-kümesi strictliği ve bundle_event_count↔close.entries uyuşması
denetlenir. Değerlerin bağlanması üretici tarafında değişiklik gerektirir
(ör. ilk olayın prev'i = SHA(manifest) veya close'a manifest_digest):
bridge_version=2 işidir, alıcıdan tek başına yapılamaz.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter

BRIDGE_VERSION = 1
GENESIS = "0" * 64

# Strict şema (v1): bilinmeyen alan RED. Neden: entry_sha yalnız 7 alanı
# bağlar; hash'e girmeyen bir alan kazırsa zincir kopmaz — bu yüzden v1'de
# alan-kümesi donmuş kabul edilir (std'in D5 dersü: hash kaynaklı değilse
# görünmez). Yeni alan → bridge_version=2.
_MANIFEST_FIELDS = frozenset({
    "type", "bridge_version", "source", "watcher_id",
    "bundle_head", "bundle_merkle_root", "bundle_event_count"})
_EVENT_FIELDS = frozenset({
    "type", "bridge_version", "seq", "ts", "agent", "host",
    "rule_id", "decision", "prev_entry_sha", "entry_sha"})
_CLOSE_FIELDS = frozenset({
    "type", "bridge_version", "entries", "watch_head"})


def entry_sha(prev: str, seq: int, ts: str, agent: str, host: str,
              rule_id: str, decision: str) -> str:
    """K0 §6 bağ-formülü — üreticiyle birebir aynı (ts string, 6-dec)."""
    return hashlib.sha256(
        f"{prev}|{int(seq)}|{ts}|{agent}|{host}|{rule_id}|{decision}".encode()
    ).hexdigest()


def verify_watch_feed(lines: list[str]) -> tuple[bool, str, Counter]:
    """JSONL-satırlarını zincir-boyunca yeniden-hash'le. (ok, mesaj, karar-sayacı)"""
    if not lines:
        return False, "FAIL: akış boş", Counter()
    try:
        m = json.loads(lines[0])
    except json.JSONDecodeError as e:
        return False, f"FAIL: manifest JSON bozuk ({e})", Counter()
    if m.get("type") != "watch_manifest":
        return False, f"FAIL: ilk satır manifest değil ({m.get('type')})", Counter()
    if m.get("bridge_version") != BRIDGE_VERSION:
        return False, f"FAIL: bilinmeyen bridge_version ({m.get('bridge_version')})", Counter()
    extra = set(m) - _MANIFEST_FIELDS
    if extra:
        return False, f"FAIL: manifest'te bilinmeyen alan(lar): {sorted(extra)}", Counter()
    bundle_count = m.get("bundle_event_count")
    if not isinstance(bundle_count, int) or bundle_count < 0:
        return False, "FAIL: manifest bundle_event_count int>=0 değil", Counter()

    prev = GENESIS
    seen = 0
    last = GENESIS
    tally: Counter = Counter()
    for no, raw in enumerate(lines[1:], start=2):
        try:
            line = json.loads(raw)
        except json.JSONDecodeError as e:
            return False, f"FAIL: satır-{no} JSON bozuk ({e})", tally
        t = line.get("type")
        if t == "watch_close":
            extra = set(line) - _CLOSE_FIELDS
            if extra:
                return False, f"FAIL: close'da bilinmeyen alan(lar): {sorted(extra)}", tally
            if line.get("entries") != seen:
                return False, f"FAIL: close.entries={line.get('entries')} ≠ gerçek {seen}", tally
            if bundle_count != seen:
                return False, (f"FAIL: manifest.bundle_event_count={bundle_count} "
                              f"≠ close.entries={seen}"), tally
            if line.get("watch_head") != last:
                return False, "FAIL: watch_head son entry_sha ile uyuşmuyor", tally
            return True, f"PASS: {seen} karar · watch_head={last[:16]}…", tally
        if t != "watch_event":
            return False, f"FAIL: satır-{no} beklenmeyen tip ({t})", tally
        extra = set(line) - _EVENT_FIELDS
        if extra:
            return False, (f"FAIL: satır-{no} bilinmeyen alan(lar): "
                           f"{sorted(extra)}"), tally
        if line.get("bridge_version") != BRIDGE_VERSION:
            return False, f"FAIL: satır-{no} bilinmeyen bridge_version", tally
        seen += 1
        if int(line.get("seq", -1)) != seen:
            return False, f"FAIL: seq süreksizliği @#{seen}", tally
        if line.get("prev_entry_sha") != prev:
            return False, f"FAIL: prev_entry_sha kopuk @seq={seen}", tally
        calc = entry_sha(prev, line["seq"], str(line.get("ts", "")),
                         str(line.get("agent", "")), str(line.get("host", "")),
                         str(line.get("rule_id", "")), str(line.get("decision", "")))
        if calc != line.get("entry_sha"):
            return False, f"FAIL: entry_sha uyuşmazlığı @seq={seen} (veri-değişikliği)", tally
        prev = calc
        last = calc
        tally[f"{line.get('rule_id')}/{line.get('decision')}"] += 1
    return False, "FAIL: watch_close yok", tally


def run(path: str) -> int:
    with open(path, encoding="utf-8") as fh:
        lines = [raw.strip() for raw in fh if raw.strip()]
    ok, msg, tally = verify_watch_feed(lines)
    print(msg)
    if tally:
        for k in sorted(tally):
            print(f"  · {k}: {tally[k]}")
    print("SONUÇ:", "SAĞLAM" if ok else "RED")
    return 0 if ok else 1


def selftest() -> int:
    """Kendi-kanıtı: sentetik akış temiz→PASS; tek-alan bozulma→RED."""
    def make(quiet: bool) -> list[str]:
        prev = GENESIS
        lines = [json.dumps({
            "type": "watch_manifest", "bridge_version": BRIDGE_VERSION,
            "source": "pugio", "watcher_id": "selftest",
            "bundle_head": "a" * 64, "bundle_merkle_root": "b" * 64,
            "bundle_event_count": 3,
        }, sort_keys=True, separators=(",", ":"))]
        decisions = [("quota_exceeded", "deny"), ("replay", "deny"), ("allow", "allow")]
        for i, (rule, dec) in enumerate(decisions, start=1):
            sha = entry_sha(prev, i, "1726100000.000000", "0xag", "/api", rule, dec)
            lines.append(json.dumps({
                "type": "watch_event", "bridge_version": BRIDGE_VERSION, "seq": i,
                "ts": "1726100000.000000", "agent": "0xag", "host": "/api",
                "rule_id": rule, "decision": dec,
                "prev_entry_sha": prev, "entry_sha": sha,
            }, sort_keys=True, separators=(",", ":")))
            prev = sha
        lines.append(json.dumps({
            "type": "watch_close", "bridge_version": BRIDGE_VERSION,
            "entries": 3, "watch_head": prev,
        }, sort_keys=True, separators=(",", ":")))
        return lines

    ok, msg, _ = verify_watch_feed(make(False))
    print("temiz-akış:", msg)
    if not ok:
        return 1

    bad = make(True)
    obj = json.loads(bad[1])
    obj["decision"] = "allow"  # deny → allow kazıması: bağ kopmalı
    bad[1] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    ok, msg, _ = verify_watch_feed(bad)
    print("bozuk-akış:", msg)
    if ok:
        print("SONUÇ: RED (kazıma yakalanamadı — ALARM)")
        return 1

    # hash-dışı gizli alan: strict şema reddetmeli (D5 dersi)
    sneaky = make(True)
    obj = json.loads(sneaky[1])
    obj["note"] = "hash'e girmeyen gizli alan"
    sneaky[1] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    ok, msg, _ = verify_watch_feed(sneaky)
    print("gizli-alan:", msg)
    if ok:
        print("SONUÇ: RED (hash-dışı alan geçti — ALARM)")
        return 1

    # manifest count ile close.entries çelişkisi reddedilmeli
    lying = make(True)
    obj = json.loads(lying[0])
    obj["bundle_event_count"] = 99
    lying[0] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    ok, msg, _ = verify_watch_feed(lying)
    print("sayı-çelişkisi:", msg)
    if ok:
        print("SONUÇ: RED (sayı çelişkisi geçti — ALARM)")
        return 1

    print("SONUÇ: SAĞLAM (selftest)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="K0 §6 watch-feed doğrulayıcı (Veridict tarafı)")
    ap.add_argument("path", nargs="?", help="watch-feed JSONL dosyası")
    ap.add_argument("--selftest", action="store_true", help="dahili tutarlılık-kanıtı")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.path:
        ap.error("path gerekli")
    return run(args.path)


if __name__ == "__main__":
    sys.exit(main())
