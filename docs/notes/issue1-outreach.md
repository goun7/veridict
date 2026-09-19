# Issue #1 — independent verifier outreach (2026-09-19)

## Kanıt zaten var

`tests/test_spec_verifier_parity.py` (8 test, CI'da) kanıtladı: spec'ten
yazılmış verifier ile production verifier **temiz fixture ve 6 kurcalama
mutasyonunun hepsinde aynı sonucu** veriyor. Yani standardın uygulanabilir
olduğu makine-kontrolli. Ama bu, **bizim** implementasyonumuzun standardı
doğru okuduğunu gösterir — üçüncü birinin aynı sonuca varıp varamayacağını
göstermez. İşte #1'in kapanması için gereken o.

## Davet edilecek adaylar (alıntı yaptığımız, henüz mail atılmamış)

| Makale | Yazarlar | Neden uygun |
|---|---|---|
| 2609.12002 — "Can We Trust LLM Judges: Capability-Dependent Biases" | Gemma Zhang, Prachi Badarayani, Asmi Kumar | §5.2 jüri çeşitlilik kurallarımızı destekleyen bulgular; jury calibration bizim merkezi tasarım kararımız |
| 2606.13221 — "From Uncertain Judgments to Calibrated Rankings" | Bora Kargi, David Salinas | Aynı cluster; confidence-only-dokunma kuralımızın akademik dayanağı |

Bu iki makale, bizim "jüriyi kalibre et" çekirdek tasarımımızı yönlendiren
cluster'dan. Yani onlar konuyu zaten bilir — soğuk istek değil.

## Davet metni (kopyala-çıstır, İngilizce)

Subject: Your LLM-judge work is cited in our paper — would you verify our
standard independently?

Hi [name],

I cited your work on [judge calibration / capability-dependent bias] in a
paper I just submitted to arXiv (Veridict — an append-only evidence ledger
with offline-verifiable certificates for AI-produced work). Your finding
that judge reliability depends on capability and calibration is literally
encoded as normative rules in our §5.2 jury-diversity requirements.

I'm writing for a different reason than a citation notice. Our project's
first exit criterion is that a third party can implement our certificate
verifier from the standard alone — without reading our reference code.
We have our own from-the-spec reimplementation and a parity test proving
it agrees with production, but that is still us checking ourselves.

The ask: if you have an hour, implement a verifier against
https://goun7.github.io/veridict/standard.html — inputs are a ledger
(append-only hash chain) and a certificate; output is a verdict. Any
language. The test vectors are at
https://github.com/goun7/veridict/tree/main/docs/standard-test-vectors

The real prize is not a passing implementation. It is every point where
the standard is ambiguous or wrong — we credit those as errata in §14.2
and they are the highest-value outcome for us. If the standard is not
implementable from the text alone, we want to know that more than we want
a pass.

If this isn't your thing, no reply needed — the citation notice stands
either way.

Göktağ
https://github.com/goun7/veridict

## Kurallar

- 2 hafta cevap gelmezse takip etme (önceki kural)
- Aynı kişiye tekrar mail atma
- Endorsement maili ile karıştırma — bu ayrı bir istek
- Onboarding kit: `docs/verifier-onboarding.md` (tuzaklar dahil)
