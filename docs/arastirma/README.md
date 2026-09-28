# Araştırma — kanıt boşluğunun akademik ve standart haritası

Bu dizin, Veridict'in "iddia değil, kanıt" tezini **dış kaynaklarla**
destekler: hangi akademik çalışmalar kanıt boşluğunu doğruluyor, hangi
standartlar uyumlu, ve hangi on-chain model aynı soruyu farklı bir
güven köküyle yanıtlıyor.

## Boşluk ne?

Bir ajan "ödendi" / "yaptım" / "çalışıyor" diyebilir. **Bağımsız bir
üçüncü taraf, elinde sadece bu iddia varken, onu nasıl doğrular?** Mevcut
cevapların çoğu güveni bir aracıya taşır (platform API'si, ödeme
sağlayıcısı, yayınlanan bir pano). Veridict'in cevabı farklı: kanıt,
**kendiliğinden hesaplanabilir** (content hash + imza + zaman damgası aynı
dosyada) ve **hash-chained bir ledger'da izlenebilir** — güvenilen bir
üçüncü taraf gerektirmez.

Aşağıdaki çalışmalar bu boşluğu farklı açılardan doğruluyor ve her biri
için Veridict'in hangi tasarım kararına karşılık geldiği belirtilmiştir.

## Belgeler

| Belge | Konu |
|---|---|
| [dijital-sertifika-guvenligi-akademik-harita.md](dijital-sertifika-guvenligi-akademik-harita.md) | 2025–2026 akademik literatür: agent kimlik, onaylı yetki, imzalı makbuz, pazar yeri sertifikasyonu |
| [w3c-verifiable-credentials-uyumu.md](w3c-verifiable-credentials-uyumu.md) | W3C VC Data Model v2.0 + Data Integrity 1.0 ile uyum ve bilinçli sapmalar |
| [eas-on-chain-kanit-modeli.md](eas-on-chain-kanit-modeli.md) | Ethereum Attestation Service: on-chain kanıt modeli ve off-chain trade-off |

## Özet tablo — her kaynak neyi doğruluyor

| Kaynak (gerçek link) | Yayın | Doğruladığı boşluk | Veridict'te karşılığı |
|---|---|---|---|
| [NostrAgent](https://arxiv.org/abs/2609.22944) (arXiv:2609.22944) | 2026-09, AGENTICS 2026 | Agent kimlik + yetki + ödeme beşlemesi parçalanmış; her yetki kararının **offline yeniden oynatılabilir** olması gerektiği | Append-only ledger + offline `veridict verify`; revocation zamanında |
| [terms.txt](https://arxiv.org/abs/2609.11152) (arXiv:2609.11152) | 2026-09, IEEE Internet Computing'a sunuldu | Agentlı web erişimi için **imzalı makbuzlar** + HTTP 402 müzakeresi; robots.txt ifadenin yetersizliği | Receipt katmanı: imzalı, standalone doğrulanabilir makbuz |
| [LEGIT](https://arxiv.org/abs/2609.21325) (arXiv:2609.21325) | 2026-09 | Agent pazar yerlerinde alıcıların performansı **doğrulayamaması**; "ölçüm + kanıt"ın imzalı kayda bağlanması | Sertifika: ödünleşmez, replay-edilebilir, ölçümleri kanıtlara bağlama |
| [Cartograph](https://arxiv.org/abs/2609.30293) (arXiv:2609.30293) | 2026-09 | MCP araç keşfinde **Ed25519-imzalı yetenek kartları** ve provenans kaydı | MCP server: operator-imzalı araç yüzeyi; core stdlib-only |
| [Proof-of-Continuity](https://arxiv.org/abs/2607.08906) (arXiv:2607.08906) | 2026-07 | Sahipliğin (token) yetersizliği; her adımın **nedensel zincirle** önceki adıma bağlı olması | Hash-chained ledger: her girdi prev_hash + yazar + ts ile bağlı |
| [SS-ZKR](https://arxiv.org/abs/2606.00962) (arXiv:2606.00962) | 2026-05 | A2A/MCP + W3C DID/VC ile **kriptografik agent kimliği**; güven sınırlarında yönlendirme | Standart-tabanlı kimlik + imza; transport-agnostic kanıt |
| [W3C VC Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/) | 2025-05-15 (REC) | Üç taraf modeli: issuer / holder / verifier | Sertifika = credential; `veridict verify` = verifier |
| [W3C VC Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/) | 2025-05-15 (REC) | Kriptografik proof over canonical document | `canonical_json` + Ed25519 + embedded public key |
| [EAS](https://attest.org/) | canlı | Şema-bazlı on-chain/off-chain attestation; **AI Eval Result** şeması örneği | Sertifika yapısının alan-bazlı karşılığı (skor + dataset hash + run id) |
| [x402](https://x402.org/) | canlı standart | HTTP-native ödeme: 402 → öde → erişim; "agentic payments at scale" | Ödeme sonrası **kanıt**: receipt = ödenen işin makbuzu |

## Bu araştırma nasıl kullanıldı

Bu kaynaklar **doğrulama** için, abartı için değil. Hiçbir makale Veridict'i
alıntılamıyor ve hiçbir şekilde öyle ima edilmiyor. Üç somut tasarım
kararı bu haritadan doğrudan izlenebilir:

1. **Public key + timestamp'in sertifikanın içine gömülmesi** (Data
   Integrity 1.0'ın "proof over the canonical document" ilkesi ve
   Cartograph'ın Ed25519-imzalı kartları) — standalone doğrulama ancak
   böyle mümkün.
2. **Revocation'ın append-only ledger girdisi olması** (NostrAgent'ın
   "replayable offline" ve EAS'ın revocable attestation'ı) — sertifika
   asla yeniden yazılmaz, iptal zincire yazılır.
3. **Receipt'lerin audit sertifikalarıyla aynı subject şemasını paylaşması**
   (LEGIT'in "bind measured quality and cost to evidence through a signed
   record" modeli) — tek bir standalone verifier iki belge türünü de
   doğrular.

## İlgili proje içi belgeler

- [docs/specs/2026-09-10-veridict-standard-v1.0.md](../specs/2026-09-10-veridict-standard-v1.0.md) — standart
- [docs/commercial-model.md](../commercial-model.md) — açık-çekirdek ticari model
- [docs/notes/paper-draft-veridict-2026.md](../notes/paper-draft-veridict-2026.md) — proje içi taslak makale
