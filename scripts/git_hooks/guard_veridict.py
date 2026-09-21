#!/usr/bin/env python3
"""VERIDICT pre-commit guard — K3 alıcı-sözleşmesi (AGENT_MESH_PROTOCOLU).

63-Sester watch-feed alıcısı (`scripts/pugio_watch_receiver.py`) pür-stdlib
ve source-agnostic'tir (bilinçli tasarım — K0 §6). Guard yalnız kendi-kanıtı
(selftest: temiz→PASS, kurcalanmış→RED) her commit'te yeniden kanıtlar.

İkinci görev: D21 disiplini. e345259 ladder davranışını değiştirdi (D14) ama
truth table'ı yenilemedi; suite yeşil kaldı ve Lean buildi ancak inspect
edildiğinde sorryAx'ın `agree`'in axiom listesinde olduğunu gösterdi — yani
formal çekirdeğin referans uygulamayla uyumu kanıtlanmamıştı. Bir commit
ladder.py'yi DEĞİŞTİRİYORSA, makbuzu da AYNI commit'te içermelidir; değilse
guard, tıpkı Lean build'inin kimse tarafından çalıştırılmadığı durumda yaptığı
gibi, başarılı görünen bir değişikliği reddeder.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RECEIVER = ROOT / "scripts" / "pugio_watch_receiver.py"
LADDER = ROOT / "veridict" / "ladder.py"
RECEIPT = ROOT / "docs" / "receipts-ladder-verification.json"
TRUTH_TABLE = ROOT / "proofs" / "ladder" / "TruthTable.lean"


def _check_receipt_freshness() -> int:
    """D21: ladder.py değiştiyse makbuz bu commit'te yenilenmiş olmalı."""
    diff = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--", str(LADDER.relative_to(ROOT))],
        cwd=ROOT, capture_output=True, text=True, timeout=30)
    if LADDER.relative_to(ROOT).as_posix() not in diff.stdout.split():
        return 0  # ladder.py bu commit'te yok — bir şey yenilenmek zorunda değil
    src = LADDER.read_bytes()
    new_sha = hashlib.sha256(src).hexdigest()
    try:
        committed = json.loads(RECEIPT.read_text())
    except (OSError, json.JSONDecodeError):
        print("\033[1;31m[VERIDICT-guard] RED: ladder.py değişti ama "
              "receipt okunamıyor\033[0m")
        return 1
    if committed.get("ladder_source_sha256") != new_sha:
        print("\033[1;31m[VERIDICT-guard] RED: ladder.py değişti, receipt "
              "eski. Önce çalıştır:\n"
              f"  python3 scripts/verify_ladder.py\n"
              f"  python3 scripts/export_lean_truth_table.py\n"
              f"Sonra 'lake env lean TruthTable.lean' ile axiom listesinde "
              "sorryAx OLMADIĞINI doğrula (erratum D21). Bu, aksiyom "
              "listesindeki sorryAx'ın kimsenin çalıştırmadığı bir Lean "
              "build'i başarılı gösterdiği e345259 sınıfıdır.\033[0m")
        return 1
    # TruthTable.lean içindeki placeholder digest'lar da örtüşmeli.
    tt = TRUTH_TABLE.read_text()
    if new_sha not in tt:
        print("\033[1;31m[VERIDICT-guard] RED: ladder.py değişti, "
              "TruthTable.lean'ın header digest'ları eski.\n"
              "Çalıştır: python3 scripts/export_lean_truth_table.py\033[0m")
        return 1
    print("\033[1;32m[VERIDICT-guard] D21: ladder.py + receipt + truth table "
          "aynı commit'te yenilendi\033[0m")
    return 0


def main() -> int:
    print("\033[1;36m== VERIDICT pre-commit guard (K3 alıcı) ==\033[0m")
    if not RECEIVER.is_file():
        print("\033[1;33m[VERIDICT-guard] alıcı yok — guard nötr geçer\033[0m")
        return 0
    r = subprocess.run([sys.executable, str(RECEIVER), "--selftest"],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        print(f"\033[1;31m[VERIDICT-guard] RED: K3 selftest kırık "
              f"({r.stdout} {r.stderr})\033[0m")
        return 1
    print("\033[1;32m[VERIDICT-guard] K3 selftest: temiz-KABUL + "
          "kurcalanmış-RED kanıtlandı\033[0m")
    return _check_receipt_freshness()


if __name__ == "__main__":
    sys.exit(main())
