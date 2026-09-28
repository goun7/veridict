# Dijital sertifika güvenliği — 2025–2026 akademik harita

**Soru:** "Ajan yaptı/ödendi" iddiası, bağımsız bir üçüncü taraf tarafından
elindeki tek dosyayla nasıl doğrulanır? Akademik literatür bu soruyu
"proof gap" (kanıt boşluğu) olarak çeşitli açılardan ele alıyor. Bu belge,
2025–2026'da yayınlanmış ve **gerçek linklerle doğrulanmış** çalışmaları
toplar ve her birinin Veridict tasarımına ne kattığını söyler.

Dikkat: bu bir alıntı derlemesi değildir. Hiçbir çalışma Veridict'ten
bahsetmez; burada incelenen ortak boşluk ve tasarım kararlarıdır.

---

## 1. Agent kimlik, yetki devri ve ödeme beşlemesi

### NostrAgent — arXiv:2609.22944 (2026-09-19)

[https://arxiv.org/abs/2609.22944](https://arxiv.org/abs/2609.22944)

Otonom ajanların beş yeteneği (kalıcı kimlik, kapsamlı yetki devri, akran
güveni, keşif, ödeme) bugün ayrı sistemlerde yaşıyor; yazarlar bunun
"yetki, güven ve ödeme"nin tam da süreklilik gereken yerde (anahtar
döndüğünde veya yetki geri alındığında) koptuğunu savunuyor. Çözümleri
imzalı olaylar zinciri ve her yetki kararının **offline'dan yeniden
oynanabilir** olması; ölçümleri arasında **sub-millisecond offline
verification** ve lineer delegasyon zinciri ölçeklendirmesi var (AGENTICS
2026'da tam makale olarak kabul edildi).

**Veridict'e kattığı:** offline-yeniden-oynatılabilirlik bir özellik değil,
bir gereklilik olarak doğrulandı. Veridict'in `veridict verify` komutu tam
olarak bu özelliği kendi güven köküyle (hash-chained ledger + Ed25519)
sağlar. Ayrıca revocation'ın "yetki geri alındığında kopma" noktası
olduğu tasarımımızla örtüşür: `receipt.revoked` / `certificate.revoked`
zincirin sonuna yazılır ve doğrulama bunu gerçeği olarak okur.

---

## 2. İmzalı makbuzlar ve agentlı web erişimi

### terms.txt — arXiv:2609.11152 (2026-09-10)

[https://arxiv.org/abs/2609.11152](https://arxiv.org/abs/2609.11152)

Açık web'in örtük anlaşması (crawler'lar girer, arama motorları ziyaretçi
gönderir) AI crawler'ları altında bozuluyor. robots.txt kimlik, amaç,
şart veya fiyat ifade edemiyor ve atlanabiliyor. Yazarlar `terms.txt`
adlı, yol ve amaca göre makine-erişim şartlarını belirten bir protokol ve
bunun **"signed receipts"** (imzalı makbuzlar) + Web Bot Auth imzaları +
HTTP 402 müzakeresi ile uygulanmasını tanımlıyor. Dependency-free
uygulama başına isteğe **0.20–0.65 ms** ekliyor (IEEE Internet Computing
özel sayısına sunuldu).

**Veridict'e kattığı:** "imzalı makbuz" kelimesi akademik bir terim olarak
bu çalışmanın merkezinde — kanıtın en küçük biriminin bir makbuz olduğu.
Veridict receipt katmanı (mcp/ altındaki `issue`/`verify`/`revoke`/`list`)
aynı ilkeyi farklı bir güven köküyle uygular: terms.txt imzayı web
kimliğine (Web Bot Auth) bağlarken, Veridict imzayı hash-chained bir
ledger'ın issue ettiği yerel anahtara bağlar. Bu çalışma, "402 ödendi"
iddiasının ancak imzalı bir makbuzla bağımsız doğrulanabilir olduğunu
kanıtlar — tam olarak x402 ekosisteminin "proof-of-done" tartışmasının
akademik karşılığı.

---

## 3. AI agent pazar yerlerinde sertifikasyon

### LEGIT — arXiv:2609.21325 (2026-09-18)

[https://arxiv.org/abs/2609.21325](https://arxiv.org/abs/2609.21325)

Agentic pazar yerlerinde alıcılar hangi ajanın görevinde en iyi
performans göstereceğini belirleyemiyor; bildirilen benchmark skorları
görevler, yazılımlar ve bütçeler arasında doğrulanamaz veya
karşılaştırılamaz. LEGIT, **sertifikasyon + itibar + pazar yeri dağıtımı**
bağlayan bir protokol sunar: "sertifikasyon, ölçülen kalite ve maliyeti
çözülen görev başına bir agent konfigürasyonu, görev alanı, değerlendirme
bütçesi ve **kanıt** ile imzalı bir kayda bağlar". Ayrıca bir Sybil saldırı
modeli altında itibar manipülasyonu için gereken depozito ve ücretleri
miktarlaştırır.

**Veridict'e kattığı:** bu, "kanıt = kalıcı" tezimizin doğrudan akademik
doğrulaması. LEGIT'in "ölçümü imzalı kayda kanıtla bağlama" modeli tam
olarak Veridict sertifikasının yapısı: verdictler, kanıt ID'leri, policy
ref ve risk seviyesi tek bir imzalı belgede; offline replay ile yeniden
hesaplanabilir. İkinci katman — itibarın geçmiş görev çıktılarına
bağlanması — Veridict'in calibration ledger'ının (üreticilerinin
çürütülen iddialarını indirimleyen) motivasyonunu yansıtır.

---

## 4. MCP araç keşfinde imzalı yetenek kartları

### Cartograph — arXiv:2609.30293 (2026-09-13)

[https://arxiv.org/abs/2609.30293](https://arxiv.org/abs/2609.30293)

Model Context Protocol araç keşfini O(n) katalog taramasından O(k)
aşamalı ifşaya taşımak için üç mekanizma: (1) **operator-attested
capability cards** — dağıtıcı operatörün kontrolünde üretilen,
**Ed25519-imzalı** açıklamalar (yayıncı kopyası yerine), (2) üç katmanlı
karıştırılabilir-küme analizi, (3) sunucuları araçlar önce sıralayan iki
aşamalı Retrieval. 22 sunucu / 374 araçlık bir deployment'da üç proxy
aracı gösteriyor; sıralamanın provenans'ını her sorgu için kaydediyor.

**Veridict'e kattığı:** MCP yüzeyinde imzalama ve provenansın zaten
akademik bir beklenti olduğunu doğrular. Veridict'in MCP server'ı
(`mcp/`) aynı prensibi araç tanımlarına değil, araçların **çıktısına**
uygular: her `issue` çağrısı Ed25519-imzalı bir receipt üretir ve
provenansı hash-chained ledger'a yazar. Operatör imzası Cartograph'ta
"kimin kontrolünde üretildiğini" gösterir; Veridict'te "bu belgeyi kimin
anahtarının imzaladığını" gösterir (embedded public key ile herkes
tarafından kontrol edilebilir).

---

## 5. Nedensel zincir ve sahipliğin yetersizliği

### Proof-of-Continuity — arXiv:2607.08906 (2026-07-09)

[https://arxiv.org/abs/2607.08906](https://arxiv.org/abs/2607.08906)

Proof-of-Possession modelleri (token, credential, capability sahibi
olmak) dağıtık yürütme zincirleri için yetersiz: sahipliğin talebin
kaynağı ile sonraki adımlarda kullanılan yetki arasındaki **nedensel
ilişkiyi** koruyamadığını savunuyor. Proof-of-Continuity'de her yürütme
adımı bir öncekine nedensel bağlı olmalı ve yalnızca nondan-gelen
yetkinin genişlemeyen bir alt kümesini iletebilir. "Proof of
Relationship" adlı tek-adımlı ilkel ve onun geçişli bileşimi tanımlanır;
confused deputy koşulu bu modelde geçerli bir davranış olarak ifade
edilemez.

**Veridict'e kattığı:** hash-chained ledger'ın teorik gerekçesi. Her
ledger girdisi `prev_hash` + payload digest + sıra + yazar + zaman
damgası + şema sürümünü bağlıyor; bu "her adımın öncekine nedensel bağlı
olduğu" ilkesinin somut uygulaması. Sertifikadaki `ledger_anchor` ise
bu zincirin bir önekine imzalı bir sabitleme (pin) yapar — replay
sadece o önek içindeki kanıtlardan yapılır, sonradan eklenen bir girdi
verdict'i değiştiremez.

---

## 6. Standart-tabanlı agent kimliği

### SS-ZKR — arXiv:2606.00962 (2026-05-31)

[https://arxiv.org/abs/2606.00962](https://arxiv.org/abs/2606.00962)

Agentlar-arası birlikte çalışabilirlik standartları (A2A, MCP) ve W3C
DID + Verifiable Credentials tabanlı kimlik çerçeveleri kriptografik
agent kimliği sağlarken, içeriğe-dayalı gizli yönlendirmeyi (payload
şifrelenmeden güven sınırlarını geçen semantik yönlendirme) destekleyen
protokol olmadığını belirtiyor. GDPR/HIPAA/MiFID altında uyum ortamları
için hard bir kısıt olarak zero-knowledge yönlendirme öneriyor.

**Veridict'e kattığı:** MCP + W3C VC/DID yığını agent kimliği için zaten
kurulmuş bir beklenti. Veridict bu yığının "credential" ve "verifier"
tarafını doldurur: bir ajan (veya onu çalıştıran) imzalı bir makbuz
tutar, herhangi bir MCP istemcisi `verify` aracıyla bağımsız doğrular.
Özellikle gizlilik tarafında bilinçli bir fark: SS-ZKR payload'ı
şifreliyor, Veridict ise kanıtı herkese açıkça doğrulanabilir tutuyor
(redaction seviyeleri `LOCAL_ONLY`/`REDACTED`/`FULL` ile belge içeriğini
ayrı tutarak).

---

## Ortak bulgu — boşluk gerçek

Bu altı çalışma farklı köklerden (kimlik, web altyapısı, pazar yeri, araç
keşfi, yetki yayılımı, birlikte çalışabilirlik) aynı noktaya geliyor:

> Sahiplik veya iddia yeterli değil; **bağımsızca yeniden hesaplanabilir
> ve nedensel olarak bağlı** bir kanıt gerek.

Hiçbiri "ödendi/uygulandı" iddiasının standalone doğrulanması için
stdlib-only, off-chain, hash-chained bir referans uygulama sunmuyor —
hepsi ya bir web kimliği, bir blockchain, veya merkezi bir kayıt
varsayıyor. Bu boşluk, Veridict'in fırsatıdır: **Ray = commodity. Kanıt =
kalıcı.**

## Sınırlar (dürüst not)

- Bu çalışmaların hiçbiri Veridict'i alıntılamaz veya ondan bahsetmez.
- terms.txt ve NostrAgent ödeme katmanını blockchain (L402/Lightning)
  üzerine kurarken, Veridict bilinçli olarak off-chain ve stdlib-only
  kalır — bu bir üstünlük değil, farklı bir güven kökü ve farklı bir
  dağıtım kısıtı (sıfır sermaye, sıfır ağ bağımlılığı).
- LEGIT'in Sybil modeli, itibar manipülasyonu için depozito gerektirir;
  Veridict'in calibration ledger'ı depozito değil, üretici indirimi
  kullanır — farklı tehdit modeli, farklı ekonomi.
