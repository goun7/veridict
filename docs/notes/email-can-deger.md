# E-posta — Can Değer (candeger@creatorstation.com)

GÖNDERİM NOTU (kendi notun, göndermeden önce sil): İmzadaki [Adınız]
yerine gerçek adını yaz. Dilersen altına GitHub kullanıcı adını da
ekleyebilirsin. Metni olduğu gibi kopyala; linkler en sonda.

---

## Konu Başlığı

Ajanların Discord açması vidyon hakkında — bu alana girmiş biriyim, bir bakmanı isteyecektim

## Gövde

Selam Can,

Kanalını takip ediyorum, "Olm AI'lar Kendi Aralarında Discord Açmış"
vidyonuz da beni hem güldürdü hem düşündürdü. O "biz daha protokol
yazıyoruz, bunlar kendi aralarında Discord açmış" repliği çok
doğruydu. Videoda anlattığın hadise de — 1200 ajan, "izole kalın"
denmesine rağmen ortak bir depo bulup kendilerine 70 bin mesajlık bir
pano örgütlemiş — kafamda bir süredir döndürdüğüm şeyin artık hayal
olmadığının kanıtı gibi geldi. Çünkü senin çıkardığın sonuç ("ajan
kimliği çözülmemiş problem, insan güvenlik metrikleri ajana aktarılamaz")
benim yaklaşık iki aydır üstünde çalıştığım problemin ta kendisi.

Projeyi kısaca anlatayım: Veridict diye bir denetim protokolü
geliştiriyorum. Özetle, yapay zekanın ürettiği iş adımlarının her biri
ekleme-silinmez, hash zincirli bir deftere yazılıyor. Her kaydın
hash'i yazarını matematiksel olarak bağlıyor; geriye dönük bir
değişiklik gizlice kalmıyor, zinciri kırıyor. Kanıt yoksa sonuç
"geçti" olmuyor, "kanıt yetersiz" bayrağı takılıyor — yani sessizlik
hiçbir konfigürasyonda başarıya benzemiyor. Sertifika, veren tarafa
güvenmeden offline olarak yeniden oynatılıp doğrulanabiliyor;
standart dokümanı sadece okuyarak yazılmış, kod tabanını hiç
görmeyen bir doğrulayıcı bile denediğimiz 8 hata modunun 8'inde aynı
hükümlere ulaşıyor. Videonda sorduğun "bu ajan kim, kimin adına
çalışıyor, yetkisi nereden geldi, diğeri neden ona güvenmeli"
dörtlüsü neredeyse birebir bu defterin şemasına denk düşüyor.

Şimdi itiraf edeyim: tek kişilik bir proje bu, sermaye ya da sponsor
yok; çekirdek Apache-2.0 ve açık kalacak. Şu an 223 test üç Python
sürümünde CI'da yeşil, sistem kendi kendini denetliyor, 1500 mutasyonlu
defterle yaptığımız bütünlük saldırısında da sessiz geçiş sıfır çıktı.
Ama bunların hiçbiri dışarıdan birinin bakması kadar değerli değil —
projenin ilk çıkış kriteri zaten "birisi bağımsız doğrulayıcı yazsın ve
bize nerede yanlış ya da belirsiz olduğunu söylesin" diye tanımlı.

Asıl söylemek istediğim şu: bu konu kanalının gündemine oturuyorsa ve
repoya bakınca "bunda bir şey var" dersen, onu kamera önünde test etmeni
çok isterim. "Fikir güzel ama şurası saçmalık" dersen bile benim için
değerli — o eleştiri tam da ihtiyacım olan şey. İstersen sana kısa bir
demo senaryosu hazırlarım, defteri kırma denemesi dahil.

Repo: github.com/goun7/veridict
Dokümantasyon ve standart: goun7.github.io/veridict

İyi çalışmalar,
[Adınız]

---

## Kendine not (gönderirken sil)

- Konu başlığı kısa ve muğlak bilinçli: merak uyandırıp spam-gibi
  görünmemek arasında deneyip en doğal hali bu. Uzun başlıklar satış
  e-postası kokuyor.
- Gövdede link sadece sonda iki tane; metnin içinde link vermek de
  "tanıtım yazısı" hissi veriyor. Gövdede link istemezler, sonunda
  görürler.
- Bağış/para konusuna hiç girmiyor: daha ilk adımda para konuşan
  e-postayı kimse ciddiye almıyor. Önce güven.
- "İtiraf edeyim" paragrafı bilinçli: tek kişi + sermayesiz demek
  zayıflık değil, samimiyet işareti. İnsanlar cilayıp parlatılmış
  girişim SPAlarından çok tek kişilik dürüst projelere ilgi
  gösteriyor.
- İsim, unvan ya da eklemek istediğin kişisel bir dokunuş varsa
  imzaya ekle — tek ortak nokta bile cevap alma ihtimalini artırır.
  (Örnek: aynı dağıtımı kullanıyor olmak, aynı Black Hat sunumunu
  izlemiş olmak gibi. Uydurma ama; sadece gerçekse yaz.)
