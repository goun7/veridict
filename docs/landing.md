# Veridict — Landing page hazırlığı

> **Ray = commodity. Kanıt = kalıcı.**
> Ajanınız işi yaptı diyor. Gerçekten yaptığını **kendiniz**
> doğrulayabiliyor musunuz?

---

## Hero (30 saniyede)

**Veridict, AI çıktısının üzerine imzalı, bağımsızca doğrulanabilir kanıt
katar.** Bir ajan bir iş tamamladığında — bir deploy, bir ödeme, bir
refactor — elinde sadece bir iddia kalmaz: hash-chained bir ledger'a
yazılmış, **herkesin yeniden hesaplayabileceği** bir content hash,
Ed25519 imzası ve imzalı zaman damgası taşıyan bir sertifika alır.

Doğrulamak için bize, bir platforma veya bir blockchain'e güvenmeniz
gerekmez:

```bash
veridict verify receipt.json     # tek dosya, sıfır bağımlılık, offline
```

İddia silinir, kanıt kalır.

---

## Problem — neden ihtiyaç var

Bir ajan "ödendi", "deploy edildi", "testler geçti" diyebilir. Bugün
bunu kontrol etmenin yolu: platformun panosuna girmek, API çağırmak veya
ajan yayıncısına güvenmek. Yani **güveni bir aracıya taşımak**. O aracı
bozulursa, satılırsa veya kapandıysa kanıt da gider.

Akademik literatür bu boşluğu "proof gap" olarak doğruluyor — altı bağımsız
2025–2026 çalışması farklı köklerden aynı noktaya varıyor. Tam haritayı
[docs/arastirma/](arastirma/README.md)'da.

## Çözüm — üç katman

| Katman | Ne sağlar | Komut |
|---|---|---|
| **Receipt** (proof-of-done) | bir başarı için imzalı, standalone makbuz | `veridict receipt issue` |
| **Audit** | makine-kanıtları + jüri + ladder ile tam denetim, offline replay | `veridict audit` |
| **MCP** | AI ajanlarının sertifika alıp doğrulaması | `mcp/` altında 4 araç |

Her katman **append-only, hash-chained**: girdiler `prev_hash` + payload
digest + sıra + yazar + zaman damgasıyla bağlı; sertifika asiden
değiştirilemiyor, sadece yeni girdi eklenebiliyor. İptal bile zincire
yazılır — belgeye dokunulmaz, imza bozulmaz, denetlenebilir kalır.

MCP server'ı kayıt-publishable formatta hazırdır (`mcp/mcp.json` +
`mcp/smithery.yaml`); Smithery / Glama / mcp.so için adım-adım rehber
[`mcp/REGISTRIES.md`](../mcp/REGISTRIES.md)'dedir. Kayıt **yapılmadı**,
kullanıcı onayı bekleniyor, maliyet $0 (yalnızca ücretsiz tier'lar).

## Çalışan örnek (gerçek komutlar)

```bash
pip install veridict-standard

# 1) ajan işi tamamladı → imzalı makbuz
export VERIDICT_HOME=$PWD/.veridict
veridict receipt issue \
  --achievement "deployed api v2 to staging" \
  --actor agent-7 \
  --evidence "gh run 8812 passed" \
  --evidence "canary 5xx 0.0%"

# 2) patron/müştim bunu bağımsız doğruluyor — dosyadan başka bir şey değil
veridict verify .veridict/receipts/<cert_id>.json

# 3) issuer'ın ledger'ı elinizdeyse: zincir + iptal durumu da
veridict receipt verify --cert .veridict/receipts/<cert_id>.json \
  --ledger .veridict/ledger.jsonl
```

`verify` çıktısı (standalone):

```json
{ "valid": true, "standalone": true,
  "signature_valid": true, "content_hash_valid": true,
  "timestamp_valid": true, "errors": [] }
```

Kurcalamayı yakalar: gövdedeki tek bit imzayı, `cert_id`'deki tek rakam
content hash'i bozar. İptal edilmiş bir receipt ledger ile doğrulanınca
`"valid": false, "revoked": true` döner.

## Sosyal kanıt (kendini denetleyen)

Veridict her CI'da **kendini denetler**: dogfood ledger + sertifika
yayınlanır, badge gerçek sertifikadan üretilir, asla elle çizilmez.

- **396 test**, 0 failed (Python 3.12–3.14)
- **1500 kurcalanmış ledger**, 5 seed → %100 yakalandı, 0 sessiz geçiş
- Offline replay `veridict verify` rc 0
- Spec-only bağımsız verifier aynı verdictlere varır (8 failure modu)

## Fiyatlandırma — para güveni kapatmaz

Açık çekirdek **sonsuza kadar Apache-2.0**. Ücretsiz katman, ücretli
katmandan **daha az güvenli değil** — aynı imzaları, aynı hashleri, aynı
bağımsız doğrulamayı içerir. Ücret, güvenin olduğu yerde değil, **insanın
yerine konamadığı yerde** alınır: hacim, destek ve sertifikasyon.

| | **Starter** $29/ay | **Team** $59/ay | **Business** $99/ay |
|---|---|---|---|
| Receipt + standalone verify | ✓ sınırsız | ✓ sınırsız | ✓ sınırsız |
| Audit (ladder + jüri + watchers) | 5/ay | 50/ay | sınırsız |
| Çalışma alanı (workspace) | 1 | 5 | sınırsız |
| MCP server (issue/verify/revoke/list) | ✓ | ✓ | ✓ |
| **Watcher sertifikasyonu** (insan incelemesi) | — | öncelikli kuyruk | öncelikli + SLA |
| Özel policy danışmanlığı | — | — | ✓ |
| Destek | community (GitHub) | öncelikli yanıt, 2 iş günü | e-posta SLA, 1 iş günü |
| Ekibe üye ekleme | — | 5 koltuk | sınırsız |

**Ne satılmıyor:** doğrulamanın kendisi. `veridict verify` hiçbir
abonelikle sınırlanamaz, kısıtlanamaz veya kapatılamaz — bu ürünün
tüm noktasıdır.

**Başlangıç kısıtı (dürüst):** izin verilen açık-çekirdek kuralı — sıfır
sermaye. Sunucu veya barındırma maliyeti olmadan başlar; ödenen şey insan
zamanı (inceleme ve destek). Ücretli katmanlar ilk ödeme/destek talebi
gelene kadar satışa çıkarılmaz (bkz. [commercial-model.md](commercial-model.md)
G3 geçidi).

## Kim için?

- **Ajan geliştiricileri** — çalışmalarına taşınabilir, doğrulanabilir
  makbuzlar eklemek için (MCP ile 4 satır).
- **Platform/pazar yeri kurucuları** — alıcıların "hangi ajan daha iyi"
  sorusunu imzalı kanıtla yanıtlamak için.
- **Uyum/denetim ekipleri** — AI çıktısının denetim izini tam, offline
  ve değiştirilemez tutmak için.
- **Ajanı ödeyen herkes** — "ödendi" iddiasını bir makbuza çevirmek için.

## Rakiplerden farkı

| | iddia/pano | blockchain attestation | **Veridict** |
|---|---|---|---|
| Bağımsız doğrulama | ✗ (aracıya güven) | ✓ | ✓ |
| Sıfır bağımlılık (stdlib) | — | ✗ (ağ/cüzdan) | ✓ |
| Offline | ✗ | kısmen | ✓ |
| Maliyet | abonelik | gas | $0 (açık çekirdek) |
| Verdict replay | ✗ | ✗ | ✓ |

## Nasıl başlanır

```bash
pip install veridict-standard
python -m veridict_receipt_mcp.server    # MCP server (mcp/ dizininden)
```

Dokümanlar: [README](../README.md) · [MCP](../mcp/README.md) ·
[Araştırma](arastirma/README.md) · [Standart](specs/2026-09-10-veridict-standard-v1.0.md)

---

*Landing copy için hazırlık dokümanı. Üst kısım hero, tablolar section
blockları olarak kullanılabilir. Fiyatlandırma modeli açık-çekirdek
etiğiyle uyumlu tutulmuştur: güven ücretsiz, insan zamanı ücretli.*
