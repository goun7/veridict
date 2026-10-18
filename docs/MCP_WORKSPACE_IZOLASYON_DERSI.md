# MCP-Workspace-İzolasyon Dersi (gece-turu, 2026-10-19)

> **Bulgu (negatif, kaydedilmesi-gereken):** veridict MCP sunucusunu
> canlı-protokol üzerinden test ederken `issue`/`revoke` araçları
> **gerçek workspace'e** (`.veridict/ledger.jsonl`, append-only) yazdı.
> Test seq 16-17 olarak deftere girdi ve bir receipt dosyası oluşturdu.

## Ne oldu

`mcp/run_server.py` üzerinde uçtan-uca bir MCP oturumu çalıştırıldı
(issue → verify → revoke → list). Araçların tamamı doğru çalıştı, ama
`workspace` argümanı verilmediği için `ReceiptWorkspace.resolve(None)`
varsayılan olarak **repo-kökündeki `.veridict/`** dizinini seçti.

Sonuç:

- `.veridict/ledger.jsonl`'e 2 kayıt eklendi: seq 16 (`receipt.issued`),
  seq 17 (`receipt.revoked`).
- `.veridict/receipts/` içinde 1 test receipt dosyası oluşturuldu.
- **Defter append-only olduğu için kayıtlar geri-silinemez** — geri-alma,
  iptal ile yapıldı (seq 17 zaten `receipt.revoked`), test-receipt
  dosyası `revoke` tarafından taşındı.

## Neden bir hata

Gece-turu kurallarının açık maddesidir: *kullanıcı-sahipli state'i
değiştirme; izolasyon-önce* (`docs/GECE_OTONOM_TURU_2026-10-18.md` §0).
Test amaçlı bir MCP oturumu, yapıyı bozan **gerçek bir yan-etki** üretti.

## Doğru-kalıp (gelecek-testler için)

MCP sunucusunu test ederken **workspace daima izole edilmeli**:

```python
# YANLIŞ — varsayılan workspace repo-köküne yazar
call(2, "issue", {"achievement": "test", "actor_identity": "t"})

# DOĞRU — workspace'i tmp_path'e yönlendir
call(2, "issue", {"achievement": "test", "actor_identity": "t",
                  "workspace": str(tmp_path / "ws")})
```

Aynısı `revoke`, `list` ve `verify` (`ledger` argümanı) için de geçerlidir.

## Kalıcı-durum (2026-10-19)

- `.veridict/ledger.jsonl`: 18 kayıt, son 2'si test kaydı (seq 16-17,
  iptal-edilmiş, `receipt.revoked` ile zincirde).
- `.veridict/receipts/`: 1 dosya kaldı (`46d3bfee…`, önceki çalışmaların).
- Deftere zarar-verilmedi (append-only zinciri bozulmadan), ama tam-
  geri-alma mümkün değildi. Kullanıcı bilgilendirilecek.

## Ne öğrenildi

1. MCP araçlarını canlı-protokol üzerinden çağırırken **her argümanın
   varsayılan-hedefini** kontrol et — varsayılan workspace, varsayılan
   DB, varsayılan ledger hep repo-köküne yazabilir.
2. Append-only defterlerde "test-verisi girme" geri-alınamaz bir eylemdir;
   test öncesi izolasyon, test sonrası temizlikten daha ucuzdur.
