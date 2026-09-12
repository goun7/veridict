# Veridict

[![CI](https://github.com/goun7/veridict/actions/workflows/ci.yml/badge.svg)](https://github.com/goun7/veridict/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)
[![Standard](https://img.shields.io/badge/standard-v1.0.0--draft-8A2BE2.svg)](docs/specs/2026-09-10-veridict-standard-v1.0.md)
[![Veridict self-audit](docs/assets/veridict-badge.svg)](https://github.com/goun7/veridict/blob/main/dogfood_cert.json)

*Doğrulamadan geçen hüküm.* | **[English](README.md)**

Veridict, **insanlar artık denetleyemediğinde yapay zekayı yapay zekayla
denetlemek** için bir protokol ve referans uygulamadır. Ekleme-silinmez
(append-only), hash-zincirli bir kanıt defteri, bir denetimin her adımını
kaydeder: yanlışlanabilir iddialar (claim), makine doğrulayıcıları, kör
heterojen bir jüri, üçüncü taraf izleyiciler (watcher) ve **herkesin
offline doğrulayabileceği** imzalı bir sertifika — denetleyene güvenmeniz
gerekmez.

Kuruluş öncülü: yapay zeka üretimi insan inceleme kapasitesini aştıkça,
insanın rolü *kod inceleyicisi* değil, **risk sahibi**dir. Veridict bu
dönüşümün etrafında inşa edilmiştir — zekanın hükmünün sahibi makine,
sorumluluğun hükmünün sahibi insandır.

## Neden bir denetim defteri

- **Sessiz geçiş yok.** Kanıt yok → INCONCLUSIVE + bayrak — asla temiz
  rapor değil.
- **Seviyeler, hisler değil.** W1a (makine gerçeği) > W1b (istatistiksel
  tekrar-üretim) > W2/W3 (jüri doktrini) — merdiven (ladder), doktrinin
  makine kanıtlarını geçersiz kılmasına izin vermez ve W3 tek başına
  asla doğrulama yapamaz.
- **Kimlik bağlayıcıdır.** Her kaydın hash'i yazarını bağlar; watcher
  manifestleri imzalıdır, W1a onlar için yapısal olarak imkânsızdır;
  kalibrasyon defteri, iddiaları çürütülmüş üreticileri iskonto eder.
- **Güvenme, doğrula.** Sertifikalar deftere karşı offline yeniden
  oynatılır. `examples/spec_verifier.py`, **yalnızca standart
  dokümanından** yazılmış (bu kod tabanını hiç import etmeyen) ve
  yayınlanan test vektörlerinden aynı hükümlere ulaşan bir
  doğrulayıcıdır.

## Hızlı başlangıç

```bash
pip install -e . && pip install pytest
# PyPI adı: `veridict-standard` (PyPI'daki çıplak `veridict` adı
# BAŞKASININ projesi — bizim değil; bu repodan veya yayınlandığında
# `pip install veridict-standard` ile kurulur)

# bir görevi uçtan uca denetle (GATE modu) — çalıştırılabilir senaryolar
# için examples/ dizinine bakın
veridict --help

# sistem kendi kendini denetler: defter → iddialar → jüri → sertifika
# → offline doğrulama
python scripts/dogfood.py

# bir sertifikayı offline doğrula (üçüncü tarafların umursadığı özellik)
veridict verify --ledger dogfood_ledger.jsonl --cert dogfood_cert.json

# standardın uygunluk (conformance) test vektörlerini yeniden üret
# (deterministik)
python scripts/build_test_vectors.py

# GATE gecikmesini tasarım bütçesine karşı ölç (§6.5: p95 < 30 dk)
python scripts/measure_latency.py
```

## Makbuzlar (iddialar değil kanıtlar)

Yukarıdaki öz-denetim rozeti, CI tarafından her push'ta gerçek dogfood
sertifikasından yeniden üretilir (asla elle çizilmez) — ve o sertifikaya
bağlanır; siz de onu kendiniz offline doğrulayabilirsiniz:
`veridict verify --ledger dogfood_ledger.jsonl --cert dogfood_cert.json`.
Başarısız bir denetim rozeti kehribar veya kırmızıya çevirir — en
kötü hüküm kazanır.

| Kontrol | Sonuç |
|---|---|
| Test süitesi | 260 passed (her iki çağrı stili, CI'da Python 3.12–3.14) |
| Öz-denetim | geçerli sertifika, risk `low`, GATE engellenmedi |
| Offline yeniden oynatma | dogfood sertifikasında `veridict verify` rc 0 |
| Kanarya (canary) protokolü | 12 hata sınıfında 10 yakalama / 3 dürüst kaçırma / 0 yanlış pozitif |
| Bütünlük saldırısı (tamper soak) | 1500 mutasyonlu defter, 5 tohum → %100 tespit, 0 sessiz geçiş |
| Standard eş-paritesi | referans doğrulayıcı ≡ salt-standart doğrulayıcı, 8 hata modunda |

CI yukarıdakilerin tamamını her push'ta koşar — makbuzlar anlatılmaz,
yeniden üretilir.

## 3 komutla watcher kaydı

```bash
veridict registry init --registry r.jsonl --key-out r.key.json
veridict registry register --registry r.jsonl --manifest examples/manifests/example-security.json --key-file r.key.json
veridict registry index --registry r.jsonl --out index.json
```

Ardından dış kayıt defterini yetkili olarak kullanarak denetleyin:
`veridict audit ... --registry r.jsonl` — iptal edilmiş (revoked)
watcher'lar reddedilir (§6.6). Kendi watcher'ınızı yazmak için
CONTRIBUTING.md'ye bakın.

## 3 komutla kendi reponuzu denetleyin

Veridict'in *kendi kodunuz* üzerinde çalıştığını görmenin en hızlı yolu:
checkout'unuzu gösteren tek dosyalık bir görev manifesti yazın, denetimi
koşun, sertifikayı offline doğrulayın — sonra çifti README'nizden bağlayın.
Çalıştırılabilir demo: [`examples/run_audit.py`](examples/run_audit.py).
(İngilizce README'deki "Audit your own repo in 3 commands" bölümündeki
komutlar birebir geçerlidir; issue şablonu:
[Audit my repo](https://github.com/goun7/veridict/issues/new?template=audit-my-repo.md).)

Her push'ta kendi CI'ınızda koşmak isterseniz reusable GitHub Action
hazır: `goun7/veridict/.github/workflows/veridict-audit.yml@v1`
(girdilerin tamamı workflow dosyasında).

## Genel site

Standart ve tasarım dokümanı **https://goun7.github.io/veridict/**
adresinde okunabilir (ve bağlanabilir) — her push'ta `main` dalından
yayınlanır.

## Dokümanlar

- **Standart (normatif taslak):** [`docs/specs/2026-09-10-veridict-standard-v1.0.md`](docs/specs/2026-09-10-veridict-standard-v1.0.md) — §14.2 hata düzeltmelerini (errata) taşır; errata önerileri birinci sınıf bir issue şablonudur
- **Standart v1.1 deltası (taslak):** [`docs/specs/2026-09-12-veridict-standard-v1.1-delta.md`](docs/specs/2026-09-12-veridict-standard-v1.1-delta.md) — WATCH transport gecikme cümlesini (D10) onaylar; v1.0 üstünden okunur
- **Tasarım dokümanı (kuruluş yazısı):** [`docs/specs/2026-09-09-veridict-design.md`](docs/specs/2026-09-09-veridict-design.md)
- **Mimari:** [`ARCHITECTURE.md`](ARCHITECTURE.md) — modül haritası → standart bölümleri
- **Strateji:** [`docs/notes/strategy-deep-review.md`](docs/notes/strategy-deep-review.md) — yol haritası + gelir, mükemmeliyetçi bakış
- **Katkı / Yönetişim / Güvenlik:** [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`GOVERNANCE.md`](GOVERNANCE.md) · [`SECURITY.md`](SECURITY.md)

## Durum ve yol haritası

Faz 1 (çekirdek) ve Faz 2 (watcher katmanı), dogfood koşusunda uçtan uca
makbuzlarla uygulanmıştır. Faz 3 (platform + standart) altyapısı yerinde:
spec taslağı, uygunluk kiti (C1–C10), pazar yeri endeksi, test vektörleri,
salt-standart doğrulayıcı. Kalan çıkış kriterleri doğaları gereği
dışsaldır:

1. başka birinin spec'ten uyguladığı **bağımsız bir doğrulayıcı**,
2. ilk **dış üretim dağıtımı**,
3. pazar yerinde **≥10 aktif watcher manifesti**.

Şu anki çalışma [`docs/plans/`](docs/plans/) serisini izler; ticari model
[`docs/commercial-model.md`](docs/commercial-model.md) içinde
belgelenmiştir.

## Katkı

Issue takipçisiyle başlayın — takipçi, projenin kendi çıkış kriterleriyle
tohumlanmıştır:

- **[Yalnızca standarttan bağımsız doğrulayıcı](https://github.com/goun7/veridict/issues/1)** (çıkış kriteri ①) — kodumuzu okumadan bir doğrulayıcı yazın; sizin ve referansın ayrıldığı her yerde ya standart belirsizdir ya da biriniz yanılıyordur ve iki bulgu da errata itibarı kazanır.
- **[Good-first issue'lar](https://github.com/goun7/veridict/labels/good-first-issue)** — örn. kanarya korpusu genişletmesi (kendi kendine yeten, referans olarak testleri de içinde).
- **[Errata önerileri](https://github.com/goun7/veridict/issues/new?template=standard_errata.md)** — yanlış, belirsiz veya uygulanamaz bir normatif cümle. Kabul edilen errata'lar §14.2'ye itibarla işlenir.

Tüm çalışma makbuz kültürüyle yönetilir: iddialar yerine testler ve
yeniden üretilmiş kanıtlar. Bkz. [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Model

Açık-çekirdek (open-core): standart, defter çekirdeği ve offline
doğrulayıcı Apache-2.0 ile — sonsuza dek — açıktır. Ticari sunumlar
(barındırılan platform, watcher sertifikasyonu, kurumsal entegrasyonlar)
üzerine inşa edilir ve açık çekirdeği asla kapamaz. Bkz.
[`docs/commercial-model.md`](docs/commercial-model.md).
