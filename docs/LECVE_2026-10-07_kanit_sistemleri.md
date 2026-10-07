# LEÇVE — Academic grounding ek (2026-10-07): kanıt sistemleri

> **README'ye eklenecek literatür ekidir.** Mevcut `README.md` içeriğine
> **dokunulmamıştır**; bu dosya `docs/` altında YENİ dosya olarak teslim
> edilmiştir (goal: doc bağlarını genişlet).
>
> **FP0:** aşağıdaki her alıntı `web_fetch` ile **HTTP-200 + tam başlık birebir
> eşleşmesi** ile doğrulanmıştır. Uydurma alıntı yoktur. Kanıt:
> [`orkestrasyon/docs/fp0_arxiv_manifest_2026-10-07.json`](../../00_TAMGA-MESH/orkestrasyon/docs/fp0_arxiv_manifest_2026-10-07.json).

---

## Academic grounding — 2026-09-22..2026-10-07 penceresi (proof-systems)

Veridict'in özü "verify-from-file-alone"dur: doğrulama için dış bir hizmete
değil, eldeki dosyanın kendisine güvenilir. Son pencerenin kanıt-sistemleri
makaleleri bu özü üç farklı açıdan destekler:

- **StateSync-GKR: Machine-Checking the Trust Chain from Sparse-Merkle State
  Transitions to GKR Verification** ([arXiv:2610.05335](https://arxiv.org/abs/2610.05335),
  Jinwook Kim (Oraclizer Core Team), cs.CR, 4 Oct 2026) — güven zincirinin
  **makine tarafından denetlenebilir** (machine-checkable) olması gerektiğini
  savunur: durum geçişleri sparse-Merkle ağaçlarına bağlanır ve her geçişin
  doğruluğu GKR (sum-check tabanlı) kanıtlarıyla otomatik olarak
  denetlenir. Veridict'in yaprak + kök + özet gömme modeli aynı
  "durum geçişi → Merkle kökü" hattını izler. **Fark:** StateSync-GKR
  bunu bir **durum makinesi için** yapar (her geçiş bir kanıt üretir);
  Veridict bir **dosya-bağlı kanıt** aracıdır — yapraklar, kök ve özet
  doğrudan dosyaya gömülüdür, böylece tek dosya hem kanıt hem doğrulayıcıdır.

- **FASTAR: FRI Accelerator for Scalable Transparent ARguments of Knowledge**
  ([arXiv:2609.25535](https://arxiv.org/abs/2609.25535), Gong/Xu, cs.CR,
  22 Sep 2026) — şeffaf (transparent, güvenilir kurulum gerektirmeyen) bilgi
  argümanlarını FRI protokolünü hızlandırarak ölçeklenebilir kılar; böylece
  "kanıt üretmek" maliyetinden arındırılmış bir araç haline gelir. Veridict'in
  tasarım felsefesiyle aynı eksen: kanıt, özel bir güven altyapısı değil,
  **herkesin çalıştırabileceği** bir algoritma olmalıdır. **Fark:** FASTAR
  FRI'nin hesap maliyetini düşürür (hız, ölçek); Veridict hesap maliyetini
  değil **güven bağımını** düşürür — sıfır kurulum, sıfır dış bağımlılık,
  saf `sha256`/Merkle.

- **Can AI Oversight Be Zero Knowledge?** ([arXiv:2610.01995](https://arxiv.org/abs/2610.01995),
  Chiesa/Guan/Yildiz, cs.AI, 1 Oct 2026) — AI denetiminde, gizli veriler
  (tıbbi kayıtlar, gizli bileşenler) üzerinden üretilen çıktıların
  **sıfır-bilgi kanıtlarıyla** denetlenip denetlenemeyeceğini sorar ve bu
  denetimin ne zaman mümkün olduğunu analiz eder. Veridict için doğrudan
  bağlamsal zemin: denetim (oversight) ile gizlilik arasındaki gerilim,
  kanıt-aracın varlık nedenidir — "ne" kanıtlandı, "nasıl" ifşa edilmeden.
  **Fark:** makale **imkân/olanak** analizi yapar (ne zaman ZK denetim
  mümkündür); Veridict gizliliği ZK ile değil, **kanıtın sadece özeti
  içermesiyle** sağlar — denetim tamamen açık, ama denetlenen içerik
  kanıtın dışında kalır.

---

*Bu ek, `README.md`'nin "Academic grounding" bölümüne eklenmek üzere
hazırlanmıştır.*
