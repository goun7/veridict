# MCP Registry Kayıt Rehberi — veridict-receipt

**Durum:** dosyalar HAZIR. **Kayıt YAPILMADI** — kullanıcı onayı bekleniyor.
Maliyet: **$0** (yalnızca ücretsiz tier'lar).

---

## 1. Smithery (öncelik)

Smithery, Arcade.dev'e katıldı (2026):
<https://arcade.dev/blog/smithery-joins-arcade>

**İki yayın yolu** (<https://smithery.ai/docs/build/publish>):

### A) Local — MCPB Bundle (bizim için uygun, stdio server)
```bash
npm install -g smithery@latest          # Node.js 20+
smithery auth login
smithery mcp publish ./veridict-receipt.mcpb -n <org>/veridict-receipt
```
- Yapılandırma hazırdır: [`smithery.yaml`](smithery.yaml)
- Manifest: [`mcp.json`](mcp.json)
- Giriş noktası: `python mcp/run_server.py` (her cwd'den; repo kökünden
  veya `mcp/`'den çalışır)

### B) URL — Streamable HTTP + OAuth (kendi host'unuz)
```bash
# 1) veridict-receipt'i HTTP uç noktası olarak yayınla
# 2) https://smithery.ai/new → HTTPS URL gir → yayınlama akışını tamamla
```
- Tarama başarısız olursa statik kart: `/.well-known/mcp/server-card.json`

**Yerel deneme (kayıtsız):**
```bash
smithery mcp add ./mcp/run_server.py --id veridict-receipt
smithery tool list veridict-receipt
smithery tool call veridict-receipt verify '{"cert":"receipt.json"}'
```

### Smithery'de konum (kanıt)
"Agent payment receipt / proof-of-delivery" kategorisi oluşmakta — Glama'da
≥6 oyuncu var. **Açık pencere:** offline-verifiable, asymmetric,
platform-bağımsız receipt. En yakın rakip `x402-receipt-verifier` kendi
README'sinde "not offline-verifiable" (HMAC-SHA256, online re-check) ve
"yalnızca NEXUS'un kendi asset'leri" diyor. veridict-receipt ise receipt'i
tek dosada doğrulatır: content hash + ed25519, ne ledger ne network.
Detay: Sester repo `docs/arastirma/mcp-pazari.md` §2.3.

---

## 2. Glama.ai

- Directory: <https://glama.ai/mcp/servers> (**93,546 server**, 2026-09-28)
- **"Add Server"** formu ile GitHub repo URL'si; README taranır.
- Kategoriler (önerilen): `Payments & Billing`, `Finance`, `Security & IAM`,
  `Autonomous Agents`
- `receipt` sorgusunda Payments & Billing kategorisinde yalnızca **9 server**
  var (2026-09-28) — niş ama sıfır değil.

---

## 3. mcp.so

- Submit: <https://mcp.so/submit?type=server>
- **Ücretsiz tier:** form → review. **$39 ödeme YAPILMAYACAK** (opsiyonel
  hızlandırma).

---

## 4. Punkpeye awesome-mcp-servers

- Repo: <https://github.com/punkpeye/awesome-mcp-servers>
- Kayıt = **PR açmak** (ücretsiz):
  `- [veridict-receipt](https://github.com/goun7/veridict) - Signed proof-of-done for AI agents; verify a receipt from the file alone.`

---

## 5. Manuel stdio config (yayın öncesi)

```json
{
  "mcpServers": {
    "veridict-receipt": {
      "command": "python",
      "args": ["mcp/run_server.py"],
      "cwd": "/path/to/Veridict",
      "env": {
        "VERIDICT_HOME": "/path/to/.veridict"
      }
    }
  }
}
```

---

## 6. Kayıt Öncesi Checklist

- [x] MCP server stdio'da çalışıyor (initialize + tools/list + tools/call)
- [x] `mcp/smithery.yaml` hazır
- [x] `mcp/mcp.json` hazır
- [x] `mcp/README.md` var (kurulum + tool listesi + örnek)
- [x] README.md'de MCP bölümü var
- [ ] **Kullanıcı onayı** → Smithery publish
- [ ] **Kullanıcı onayı** → Glama "Add Server"
- [ ] **Kullanıcı onayı** → mcp.so submit (ücretsiz tier)
- [ ] **Kullanıcı onayı** → Punkpeye PR
- [ ] Yayın sonrası: README'lere registry linkleri ekle

**Not:** API anahtarları bu dokümanda YOK. İmzalama anahtarı yerel 0600
dosyada tutulur; yalnızca PUBLIC yarısı receipt/ledger'da görünür.
