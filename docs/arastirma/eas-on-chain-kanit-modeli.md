# EAS (Ethereum Attestation Service) — on-chain kanıt modeli

**Kaynaklar (doğrulanmış, canlı):**
- [https://attest.org/](https://attest.org/) — resmi site (eski attest.sh)
- [https://docs.attest.org/](https://docs.attest.org/) — dokümanlar

## EAS ne yapıyor?

EAS, **yapılandırılmış veri hakkında imza ve doğrulama** altyapısıdır:
bir **schema** kaydedersiniz (alan adları + tipler), o schema ile
**attestation** üretirsiniz. İki modu vardır:

- **On-chain:** attestasyon bir blockchain işlemi olarak yayınlanır;
  herkes bir explorer'dan doğrular. **9.5M+ attestasyon, 450k+ attester.**
- **Off-chain:** attestasyon yerel bir depoda veya veritabanında kalır,
  **"verifiable on demand"** — yani talep edildiğinde doğrulanır.

EAS'ın örneklediği **"AI Eval Result"** şeması (#42) alaniz bakımından
çok tanıdık: `model`, `benchmark`, `resolved 392/500`, `score_bps`,
`dataset_sha` (bytes32), `run_id`. Bir modelin bir benchmark'taki sonucunu,
dataset hash'ini ve run kimliğini imzalı bir kayda bağlar — Veridict
sertifikasının **on-chain kardeşi**.

EAS'ın 2026'da vurguladığı yön "built for agents": yeni **easctl** CLI
("built for agents", "Zero API Keys") ve "Machines attesting to their
outputs — AI evals, model runs, and agent actions, signed by the machine
that produced them" kullanım örneği.

## Aynı soru, farklı güven kökü

| | EAS | Veridict |
|---|---|---|
| Kanıt birimi | attestation (schema + data + signature) | sertifika / receipt |
| Güven kökü | blockchain consensus + cüzdan anahtarı | hash-chained local ledger + Ed25519 |
| Doğrulama | on-chain: herhangi biri explorer'dan; off-chain: talep üzerine | **standalone: eldeki tek dosya** |
| Revocation | attestation'da `revocable` flag + on-chain revoke girdisi | append-only `certificate.revoked` / `receipt.revoked` |
| Maliyet | on-chain işlem ücreti (gas) | sıfır (stdlib-only, yerel) |
| Bağımlılık | bir ağın çalışır olması | hiçbiri |
| Ağ効果 | genel, global, composable | kuruluş içi, taşınabilir, denetlenebilir |

## Off-chain EAS ile ortak nokta — ve temel fark

EAS'ın off-chain modu Veridict'e en yakındır: kanıt yerel kalır, talep
edildiğinde doğrulanır. **Temel fark doğrulamanın girdisidir:**

- EAS off-chain attestasyonu doğrulamak için imzalayanın cüzdan adresini
  (ve şemayı) çözmeniz gerekir — bu, imzayı bir **blockchain kimliğine**
  bağlayan bir adımdır.
- Veridict receipt'inde imzalayanın **public key'i belgenin içindedir**.
  Doğrulama için dışarıda hiçbir şey çözmeniz gerekmez: content hash'i
  belgenin kendi alanlarından yeniden hesaplarsınız, imzayı gömülü
  public key ile kontrol edersiniz, zaman damgası imzalı gövdenin
  içindedir.

Bu, "herkes tarafından yeniden hesaplanabilir hash" gereksiniminin
neden standalone olması gerektiğinin somut karşılığıdır: EAS'te kanıt
global bir kayıt defterine; Veridict'te belgenin kendisine bağlıdır.

## EAS'ten ödünç alınan üç şey

1. **Şema disiplini.** Her attestasyon bir şemaya uyar; bu, alan
   anlamlarının önceden yayınlanmış olması demektir. Veridict'te
   `SCHEMA_VERSION` + `certificate_type` aynı rolü oynar: bir verifier
   belgeyi okumadan önce **ne okuduğunu** bilir ve uygunsuz bir tip
   reddedilir (`verify_receipt` `certificate_type != veridict-receipt-v1`
   durumunda fail-closed olur).
2. **Revocable-by-default.** EAS örneğinde "Revocable: Yes" bir alan.
   Veridict'te iptal bir flag değil, **zincire yazılmış bir olaydır** —
   ne zaman, kim, neden. Belge asla yeniden yazılmaz, imza bozulmaz,
   iptal bağımsızca denetlenebilir.
3. **"Machines attesting to their outputs."** EAS'ın bu kullanım örneği
   Veridict'in tezinin on-chain ifadesidir: makinelerin ürettiklerini
   imzalamaları. Veridict bunu her bir CI sürecinin yapabileceği, sıfır
   maliyetli, sıfır ağ bağımlılığı bir hale getirir.

## Bilinçli olarak yapılmayan şey (dürüst not)

Veridict **blockchain kullanmaz** — bu bir eksiklik değil, tasarım
kararıdır:

- **Sıfır sermaye kısıtı:** on-chain yayınlama gas gerektirir; proje
  sıfır-sermaye açık-çekirdek olarak tasarlandı (bkz.
  [commercial-model.md](../commercial-model.md)).
- **Dağıtım kısıtı:** bir ajanın receipt üretmesi için bir cüzdan
  yönetmesi (ve PRIVATE_KEY'lerle uğraşması) gerekirdi — bu hem
  güvenlik yüzeyini büyütür hem de "sıfır kurulum" vaadini bozar.
  Veridict'te anahtar yerel bir belge-imzalama anahtarıdır (0600),
  blockchain değil.
- **Kanıt zaten tam:** Veridict'in anchor özelliği **isteğe bağlı** bir
  Sigstore Rekor transparency-log bağlantısı sunar (`veridict audit
  --anchor rekor`) — isteyen için harici bir transparency kökü, ama
  çekirdek doğrulama için değil.

EAS ve Veridict rakip değil, **aynı boşluğun iki güven kökü**: EAS global
bir registry'in değiştirilemezliğini satıyor, Veridict belgenin
kendiliğinden-doğrulanabilirliğini. İkisi de "kanıt = kalıcı" diyor.
