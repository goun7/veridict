# W3C Verifiable Credentials ile uyum

**Durum:** W3C, iki ilgili standardı 15 Mayıs 2025'te **Recommendation**
(standart) seviyesine çıkardı. Bu belge Veridict sertifikasının bu
standartlara nasıl uyduğunu ve bilinçli olarak nerede saptığını söyler.

- [Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
  (W3C Recommendation, 2025-05-15)
- [Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
  (W3C Recommendation, 2025-05-15)

## Üç taraf modeli → birebir eşleme

W3C modeli üç taraflıdır: **issuer** (veren), **holder** (tutucu),
**verifier** (doğrulayan). Veridict aynı üç tarafı kullanır:

| W3C | Veridict | Not |
|---|---|---|
| Issuer | `veridict audit` / `receipt issue` | Anahtar enroll edilir; public yarısı ledger'a yazılır |
| Verifiable Credential | sertifika / receipt JSON | İçeriği + proof'u taşır |
| Holder | ajan veya onu çalıştıran | Belgeyi saklar, sunar |
| Verifier | `veridict verify` | **İndependent**: issuer'a güvenmez |
| Verifiable Data Registry | hash-chained ledger | Anahtar iptali ve provenans için |
| Presentation | cert dosyasının kendisi | Ek protokol gerekmez |

## Data Integrity 1.0 — dört ilke, dört uygulama

Data Integrity spesifikasyonu "constrained digital documents" için
crypto-secured integrity tanımlar. Dört temel ilkenin Veridict'teki
karşılığı:

### 1. Proof over the canonical document

W3C: belgenin kurallı (canonical) gösterimi üzerinden imzalama; böylece
imza belgenin tamamını kapsar ve serialization farklılıkları imzayı
bozmaz.

Veridict: `canonical_json()` — sort_keys, sıkıştırılmış separatorler,
ASCII-escape, `allow_nan=False`. NaN/Infinity'in RFC 8259'a aykırı
literaller olarak yazılmasını ve "Python'da doğrulandı, başka parser'da
bozuldu" zehirlenmesini üretici sınırında reddeder. İmza bu kurallı
gövdenin sha256'lik Ed25519 imzasıdır.

### 2. Key resolution — kimin imzaladığını bulma

W3C: proof, imzalayan anahtara işaret etmeli ve verifier bu anahtarı
çözebilmelidir (DID veya güvenilir kayıt üzerinden).

Veridict: her sertifika **public key'in kendisini gömer** (`public_key`
alanı). Bu, key resolution için bir registry sorgusu gerektirmeyen en
sadık uygulamadır: verifier, imzayı çözmek için ihtiyaç duyduğu her şeyi
belgeden alır. Ledger'daki `key.enrolled` girdisi ise **provenans**
içindir (anahtar ne zaman, hangi kimlikle enroll edildi) — standalone
doğrulama için gerekli değildir.

**Trade-off (bilinçli):** DID çözümü merkezileştirme getirir veya bir DID
yöntemi bağımlılığı yaratır. Gömülü public key sıfır bağımlılıkla maksimum
taşınabilirlik veriyor; DID tabanlı resolution ileride bir katman olabilir.

### 3. Verifier-side recomputation

W3C: verifier, proof'u belge içeriğine karşı **yeniden hesaplar**; elde
edilen değer ile stated değer karşılaştırılır.

Veridict: sadece imzayı değil, **türetilmiş alanları** da yeniden
hesaplar — `cert_id` (subject alanlarından), `risk_level`, `score`,
`divergence_summary`. Bunlar verdictlerden **follow** eden özet alanlar:
sadece verdictleri kontrol eden bir verifier, özeti serbest bırakır ve
"yeşil sahte" (REFUTED verdict + `risk_level: low`) mümkün olur.
`verify_certificate` her birini replay'dan türetip karşılaştırır.

### 4. Tamper-evident, non-repudiable

W3C: belge değiştirilirse proof geçersiz olmalı; imzalayan inkar edememeli.

Veridict: imza gövdeyi kapsar; gövdedeki tek bit değişimi imzayı bozar
(test: `test_tampered_body_breaks_signature`). İmzalama anahtarı
yereldir ve asla dışarı çıkmaz — sadece public yarısı. Non-repudiation
anahtarın korunmasına bağlıdır (0600 dosya), protokole değil.

## Bilinçli sapmalar

Veridict W3C'nin bir kümesi değil, spesifik bir problem için
optimize edilmiş bir uygulamasıdır. Üç bilinçli sapma:

1. **Proof format:** W3C `proof` alanı (type, created, verificationMethod,
   proofPurpose, proofValue) yerine sade `signatures` listesi. Çoklu
   imzacıyı ve algoritma alanını doğal destekler; W3C'nin alan adları
   implementasyona yayılmaz.
2. **Revocation:** W3C status list (bit-string credential status) yerine
   **append-only ledger girdisi** (`certificate.revoked` /
   `receipt.revoked`). Ledger'ın avantajı: iptal **zaman sıralı ve
   kendisi kanıt** — kim, ne zaman, neden iptal etti zincirden okunur,
   ayrı bir status list sunucusu gerekmez.
3. **Verdict replay:** W3C'de credential'ın içeriği issuer'ın söylediğidir.
   Veridict'te sertifika, **verdictlerin ledger'dan yeniden
   hesaplanabileceği** bir taahhüttür. `verify_certificate` bunu yapar:
   policy'yi ledger kaydından karşılaştırır, kanıtları anchored önekle
   sınırlar ve verdictleri baştan hesaplar. Standart bir VC'de olmayan
   bu özellik, "sertifika = kanıt" iddiasının özüdür.

## Yapısal eşleştirme örneği

Bir Veridict receipt'inin W3C VC'ye kavramsal çevirisi (transformasyon
değil, harita):

| Veridict receipt | W3C VC karşılığı |
|---|---|
| `schema_version` | `@version` / context |
| `cert_id` | `id` |
| `subject.actor_identity` | `credentialSubject.id` |
| `achievement` | `credentialSubject` claim |
| `issued_at` | `issuanceDate` (RFC 3339) |
| `issuer.identity` | `issuer` |
| `public_key.public_pem` | `verificationMethod` (gömülü) |
| `signatures[0].sig_b64` | `proof.proofValue` |
| `receipt.revoked` (ledger) | `credentialStatus` (status list yerine chain) |

## Sonuç

Veridict, W3C'nin iki 2025 standardının **üç taraf modelini ve Data
Integrity'nin dört ilkesini** birebir izler; sapmaların her biri belirli
bir nedenle (DID bağımlılığı yerine sıfır-bağımlılık, status list yerine
append-only kanıt, statükodan replay'e). Bu, ileride W3C uyumlu bir
projection (örneğin `veridict export --format vc` için) için zemin
hazırlar; mevcut `export --format vsa` (SLSA) ve `spdx` projeksiyonları
aynı "sertifika otoriter, projection kayıplı" kuralını izler.
