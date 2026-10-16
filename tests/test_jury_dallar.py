"""Dal-kesen (branch-cutting) testler: veridict/jury.py

Kapsanan public API:
  * _read_sources(artifact_dir)            — sınırlı kaynak okuma (jury doctrine
    girdisi; private ama jury.evaluate'ın tek dallı girdisi olduğu için
    doğrudan dal-kesen olarak test edilir)
  * Opinion (frozen dataclass)
  * ProviderError (istisna)
  * ScriptedProvider(family, identity, default, responses, version, fn, revise)
    * .doctrine(claim_summary, artifact_digest, sources=None)
  * OpenAICompatProvider(family, identity, version, base_url, api_key, model)
    * .doctrine(claim_summary, artifact_digest, sources=None)
    * ._samples() / ._temperature(n) / ._timeout()  (kalibrasyon düğmeleri)
  * Jury(providers, *, author_family=None)
    * .evaluate(claim, artifact_digest, artifact_dir=None)
    * .deliberate(claim, artifact_digest, first_items)
    * ._build_item(claim, artifact_digest, provider, opinion, round_salt)

DAL LİSTESİ:
  _read_sources: None dir -> None; olmayan dir (OSError/listdir) -> None;
    boş dir -> None; .py içermeyen dir -> None; test_ öneki hariç; .py dışı
    hariç; boş/beyaz-uzaylı .py atlanır; okunamayan dosya (dizin yolu, OSError)
    atlanır; sıralı (sorted) birleştirme "--- ad ---" başlığıyla;
    _MAX_SOURCE_FILES=6 üst sınırı; _MAX_SOURCE_BYTES=6000 üst sınırı
    (BAYT sayımı: UTF-8 kodlanmış bayt; çok-baytlı kaynakta karakter
    sayısı değil bayt bütçesi dolar, JURY-B3 düzeltmesi)
  ScriptedProvider.doctrine: responses'ta yoksa default; responses'ta varsa
    responses; fn varsa hepsini geçersiz kılar; artifact_digest/sources argümanları
    göz ardı edilir (sadece claim_summary'e bakılır)
  OpenAICompatProvider.__init__: açık base_url/api_key/model; env öntanımlıları
    (VERIDICT_JURY_URL zorunlu, anahtar "" öntanımlı, model "gpt-4o-mini"
    öntanımlı); base_url yoksa ve env yoksa KeyError
  _samples: env yok -> 1; "4" -> 4; "0" -> 1 (max zemin); "-3" -> 1;
    "abc" -> 1 (ValueError yolu)
  _temperature: env yok & n<=1 -> 0.0; env yok & n>1 -> 0.7; env geçerli float ->
    n'den bağımsız o değer; env çöp -> 0.0/0.7 yedeği
  _timeout: env yok -> 60.0; "120" -> 120.0; "5" -> 10.0 (max(10,·) zemin);
    "abc" -> 60.0
  doctrine (n=1): tek çağrı; evidence alanı yoksa rationale'ye
    " [no-evidence-field]" eklenir; evidence listesi (>=2 dolu string) varsa
    rationale "evidence: a; b | ..." olur; evidence list-değil / len<2 /
    boş-string / string-dışı -> ProviderError; stance SUPPORTS|REFUTES dışı ->
    ProviderError; confidence string'den float'a; rationale str()'e;
    HTTP hata durumu -> ProviderError; transport hatası -> ProviderError;
    bozuk JSON -> ProviderError; eksik choices/message/stance -> ProviderError;
    api_key boşsa Authorization başlığı yoksa vardır; sources varsa prompt
    kaynak bloğunu içerir, yoksa içermez; URL "/" ile bitince kırpılır;
    model+temperature payload'da
  doctrine (n>1): sıkı çoğunluk -> conf = mean(anlaşan) * (k/kullanılabilir),
    rationale " [sample-calibration: k/kullanılabilir STANCE]"; çoğunluk yok
    (sample-split) -> ProviderError; oybirliği (n=n) -> agree=1.0;
    BOZUK ÖRNEK yalıtılır (JURY-B2): hatasal örnek atılır, koşuya devam,
    rationale " [h/n sample-failed]" öneki taşır; SADECE tüm örnekler
    bozuksa ProviderError("all n samples failed")
  Jury.__init__: <2 sağlayıcı -> ValueError; 2 sağlayıcı aynı aile ->
    ValueError; >=2 sağlayıcı >=2 aile -> OK; author_family dışlama
    (büyük-küçük harf + beyaz-uzay duyarsız); author_family boş/None ->
    dışlama yok; author_family hepsini dışlarsa -> ValueError (fail-closed);
    dışlananlar .excluded listesinde
  Jury.evaluate: hepsi başarılı -> items, abstained==[]; bir sağlayıcı
    ProviderError -> abstained; evidence_id = sha256_hex(salt|claim_id|identity)[:24]
    (deterministik; claim/identity değişince değişir); producer {kind jury,
    identity, version, family}; tier W2, evidence_class JURY_OPINION;
    reproducibility {deterministic: False, rerun_recipe: None};
    artifact_dir None -> sources None; artifact_dir dolu -> sources dolu;
    dışlanan self-preference notuyla abstained'da
  Jury._build_item: round_salt değişince evidence_id değişir
  Jury.deliberate: revise hook yoksa first-round görüş korunur (r2 tuzuyla);
    revise hook varsa revised görüş; revise hook hata verirse korunur;
    packet'lar kendi identity'sini hariç tutar; first-round öğesi olmayan
    sağlayıcı abstained'a gider; hepsinde öğe varsa abstained==[]

BULGULAR (B1/B2/B3 DALGA-7-A'da ÜRETİMDE DÜZELTİLDİ, pinler yeni doğru
davranışı gösterir; B4 belgededir):
  B1 (DÜZELTİLDİ VERIDICT-JURY-B1): Jury.deliberate'in `tolerance`
      parametresi HİÇ OKUNMUYORDU — ölü parametre. İşlevsel uygulanacak
      anlamlı bir dal yoktu (sapma eşiği compute_divergence/adjudicate
      tarafında zaten uygulanıyor), bu yüzden parametre KALDIRILDI: çağıran
      artık sessizce-yok-sayılan bir ayar düğmesi geçemiyor; eski 4.
      konumlu argüman gürültülü TypeError verir.
  B2 (DÜZELTİLDİ VERIDICT-JURY-B2): OpenAICompatProvider.doctrine'un n>1
      örneklem döngüsünde _one çağrısı artık örnek BAŞINA try/except içinde:
      tek bozuk örnek bütün koşuyu ProviderError ile iptal etmiyor, atılır
      (çekimser/notr) ve koşu devam eder; yalnızca tüm örnekler bozuksa
      jüri çekimser kalır.
  B3 (DÜZELTİLDİ VERIDICT-JURY-B3): _read_sources artık KARAKTER değil
      UTF-8 BAYT sayar: okunan parça encode edilip kalan bayda kırpılır,
      total bayt artar. Çok baytlı (Türkçe) kaynakta gerçek bayt bütçesi
      aşılamaz.
  B4: ScriptedProvider.doctrine responses haritası YALNIZCA tam-string
      eşleşmeyle arar (summary'nin leading/trailing beyaz uzayı vs. farklı
      ise default döner); `fn` hem responses'ı hem default'u geçersiz kılar.
"""
from __future__ import annotations

import json

import httpx
import pytest

from veridict import jury as JURY_MOD
from veridict.jury import (
    EID_SALT,
    OpenAICompatProvider,
    Opinion,
    ProviderError,
    ScriptedProvider,
    Jury,
    _read_sources,
)
from veridict.schemas import Claim
from veridict.utils import sha256_hex


@pytest.fixture(autouse=True)
def _temiz_jury_envi(monkeypatch):
    """Sıra-bağımsızlık (modül-global os.environ kirlenmesini önler): her
    test öncesi jury env düğmeleri silinir; ihtiyacı olan test kendi
    setenv'ini yapar."""
    for k in ("VERIDICT_JURY_SAMPLES", "VERIDICT_JURY_TEMPERATURE",
              "VERIDICT_JURY_TIMEOUT", "VERIDICT_JURY_URL",
              "VERIDICT_JURY_KEY", "VERIDICT_JURY_MODEL"):
        monkeypatch.delenv(k, raising=False)


# ---------------------------------------------------------------- helpers ----

def _claim(cid: str = "c1") -> Claim:
    return Claim(claim_id=cid, task_id="t1", subject="fn",
                 predicate="idiomatic", scope="module",
                 summary=f"{cid}: fn is idiomatic", derived_from="dig",
                 verifiability="DOCTRINAL", falsifiable_by=(),
                 critical_class=None)


def _scripted(family: str, identity: str | None = None, stance: str = "SUPPORTS",
              conf: float = 0.8, why: str = "looks fine") -> ScriptedProvider:
    return ScriptedProvider(family=family,
                            identity=identity or f"{family}-1",
                            default=Opinion(stance, conf, why))


def _iki_juri(fam_a: str = "fa", fam_b: str = "fb") -> Jury:
    return Jury([_scripted(fam_a), _scripted(fam_b)])


class _Yanit:
    """Sahte httpx.Response: raise_for_status + json. AĞ YOK."""

    def __init__(self, body: dict | None = None, status_code: int = 200):
        self.status_code = status_code
        self._body = body if body is not None else {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(f"HTTP {self.status_code}",
                                        request=None, response=self)

    def json(self) -> dict:
        return self._body


def _opinion_body(stance: str = "SUPPORTS", confidence: float = 0.9,
                  rationale: str = "fine", evidence=None) -> dict:
    body: dict = {"stance": stance, "confidence": confidence,
                  "rationale": rationale}
    if evidence is not None:
        body["evidence"] = evidence
    return body


def _sahte_post(kayit: dict, yanitlar):
    """httpx.post'un yerini alan stub. `yanitlar`: _Yanit | Exception |
    (index -> _Yanit) çağrılabilir."""
    def post(url, *, headers=None, json=None, timeout=None):
        kayit.setdefault("caglar", []).append({"url": url, "headers": headers,
                                               "json": json, "timeout": timeout})
        if isinstance(yanitlar, Exception):
            raise yanitlar
        if callable(yanitlar):
            return yanitlar(len(kayit["caglar"]) - 1)
        return yanitlar
    return post


def _provider(monkeypatch, kayit: dict, yanitlar, **kw) -> OpenAICompatProvider:
    monkeypatch.setattr(JURY_MOD.httpx, "post", _sahte_post(kayit, yanitlar))
    return OpenAICompatProvider(family="fa", identity="fa-1",
                                base_url="http://mock.local/", **kw)


# ============================================================ _read_sources ==

class TestReadSources:
    """_read_sources: her başarısızlık/başarı/sınır dalı."""

    def test_none_dir_none_doner(self):
        assert _read_sources(None) is None

    def test_olmayan_dir_none_doner(self, tmp_path):
        assert _read_sources(str(tmp_path / "yok")) is None

    def test_bos_dir_none_doner(self, tmp_path):
        assert _read_sources(str(tmp_path)) is None

    def test_py_olmayan_dir_none_doner(self, tmp_path):
        (tmp_path / "a.txt").write_text("x", encoding="utf-8")
        (tmp_path / "b.md").write_text("y", encoding="utf-8")
        assert _read_sources(str(tmp_path)) is None

    def test_bos_py_atlanir_none_doner(self, tmp_path):
        (tmp_path / "bosluk.py").write_text("   \n\t\n", encoding="utf-8")
        assert _read_sources(str(tmp_path)) is None

    def test_py_dosyalarini_baslikla_birlestirir(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1", encoding="utf-8")
        (tmp_path / "b.py").write_text("y = 2", encoding="utf-8")
        out = _read_sources(str(tmp_path))
        assert out is not None
        assert out == "--- a.py ---\nx = 1\n\n--- b.py ---\ny = 2"

    def test_sorted_sirasiyla_gelecek(self, tmp_path):
        for ad in ("zeta.py", "alpha.py", "mid.py"):
            (tmp_path / ad).write_text(ad, encoding="utf-8")
        out = _read_sources(str(tmp_path))
        assert out is not None
        assert out.index("alpha.py") < out.index("mid.py") < out.index("zeta.py")

    @pytest.mark.parametrize("ad, beklenen", [
        ("test_x.py", False),
        ("test_.py", False),
        ("notest.py", True),
        ("x.py.txt", False),
    ])
    def test_test_onesiz_ve_py_disi_haric(self, tmp_path, ad, beklenen):
        (tmp_path / ad).write_text("gövde", encoding="utf-8")
        out = _read_sources(str(tmp_path))
        if beklenen:
            assert out is not None and ad in out
        else:
            assert out is None

    def test_okunamayan_dosya_atlanir(self, tmp_path):
        # "d.py" adında bir DİZİN: open() -> IsADirectoryError (OSError)
        (tmp_path / "d.py").mkdir()
        (tmp_path / "a.py").write_text("x = 1", encoding="utf-8")
        out = _read_sources(str(tmp_path))
        assert out is not None
        assert out == "--- a.py ---\nx = 1"

    def test_max_source_files_sinari(self, tmp_path):
        for i in range(8):
            (tmp_path / f"f{i}.py").write_text(f"# {i}", encoding="utf-8")
        out = _read_sources(str(tmp_path))
        assert out is not None
        assert out.count("--- ") == 6
        assert out.index("f0.py") < out.index("f5.py")

    def test_max_source_bytes_sinari(self, tmp_path):
        (tmp_path / "buyuk.py").write_text("a" * 10_000, encoding="utf-8")
        (tmp_path / "b.py").write_text("b" * 10, encoding="utf-8")
        out = _read_sources(str(tmp_path))
        assert out is not None
        # sorted sıra: "b.py" önce okunur (10 karakter), ardından "buyuk.py"
        # kalan bütçeyle (6000-10 = 5990 karakter) okunur
        assert out.startswith("--- b.py ---\nbbbbbbbbbb\n\n--- buyuk.py ---\n")
        gövde = out.split("--- buyuk.py ---\n", 1)[1]
        assert gövde == "a" * 5990

    def test_max_source_bytes_toplami_asmaz(self, tmp_path):
        for i in range(3):
            (tmp_path / f"f{i}.py").write_text("x" * 4_000, encoding="utf-8")
        out = _read_sources(str(tmp_path))
        assert out is not None
        # 4000 + 2000 = 6000; üçüncü dosya okunmaz (bütçe dolar)
        assert "f2.py" not in out
        assert "f0.py" in out and "f1.py" in out

    def test_unicode_kaynak_kabul(self, tmp_path):
        (tmp_path / "tr.py").write_text("# Türkçe açıklama: ğüşıöç\n",
                                        encoding="utf-8")
        out = _read_sources(str(tmp_path))
        assert out is not None
        assert "Türkçe açıklama" in out

    def test_butce_utf8_byte_ile_olculur(self, tmp_path):
        """BULGU B3 (DÜZELTİLDİ VERIDICT-JURY-B3): bütçe KARAKTER değil
        UTF-8 BAYT — 2-baytlık 'ş' ile 6000 karakterlik değil 6000 baytlık
        içerik döner."""
        (tmp_path / "tr.py").write_text("ş" * 5_000, encoding="utf-8")  # 10000 B
        out = _read_sources(str(tmp_path))
        assert out is not None
        gövde = out.split("--- tr.py ---\n", 1)[1]
        assert len(gövde.encode("utf-8")) == 6_000
        assert len(gövde) == 3_000                 # 3000 kar = tam 6000 bayt

    def test_cok_baytli_kaynak_toplam_byte_butcesini_asmaz(self, tmp_path):
        """Çok-baytlı ilk dosya bütçeyi BAYT olarak doldurur: sonraki dosya
        okunmaz (karakter-sayımlı eskiden 2-baytlıkta bütçe aşılıyordu)."""
        (tmp_path / "a.py").write_text("ğ" * 4_000, encoding="utf-8")   # 8000 B
        (tmp_path / "z.py").write_text("x" * 100, encoding="utf-8")
        out = _read_sources(str(tmp_path))
        assert out is not None
        gövde = out.split("--- a.py ---\n", 1)[1]
        assert len(gövde.encode("utf-8")) == 6_000
        assert "z.py" not in out

    def test_yarim_kalan_cok_baytli_karakter_dusurulur(self, tmp_path):
        """Bayt-kırpması bir karakterin ORTASINDA kalırsa yarım bayt dizisi
        değil eksik karakter döner (decode errors=ignore): çıktı her zaman
        geçerli UTF-8 ve bütçe içinde."""
        (tmp_path / "euro.py").write_text("€" * 2_500, encoding="utf-8")  # 7500 B
        out = _read_sources(str(tmp_path))
        assert out is not None
        gövde = out.split("--- euro.py ---\n", 1)[1]
        assert len(gövde.encode("utf-8")) <= 6_000
        assert gövde == "€" * 2_000                # 2000*3 = tam 6000 bayt
        gövde.encode("utf-8").decode("utf-8")      # patlamaz: yarım bayt yok

    def test_ascii_butce_davranisi_ayni_kalir(self, tmp_path):
        """B3 düzeltmesi ASCII dalını oynatmaz: 4000+2000 karakter = 4000+2000
        bayt, ikinci dosyanın tamamı alınır."""
        (tmp_path / "big.py").write_text("A" * 4_000, encoding="utf-8")
        (tmp_path / "b.py").write_text("B" * 2_000, encoding="utf-8")
        out = _read_sources(str(tmp_path))
        assert out.count("A") == 4_000 and out.count("B") == 2_000


# ======================================================= ScriptedProvider ====

class TestScriptedProvider:
    """ScriptedProvider.doctrine: default / responses / fn dalları."""

    def test_responses_tasiyorsa_onu_kullanir(self):
        p = ScriptedProvider(family="fa", identity="fa-1",
                             default=Opinion("SUPPORTS", 0.5, "öntanımlı"),
                             responses={"özel özet": Opinion("REFUTES", 0.1, "yok")})
        op = p.doctrine("özel özet", "digest")
        assert op.stance == "REFUTES" and op.confidence == 0.1

    def test_responses_tasimiyorsa_default(self):
        p = ScriptedProvider(family="fa", identity="fa-1",
                             default=Opinion("SUPPORTS", 0.5, "öntanımlı"),
                             responses={"başka": Opinion("REFUTES", 0.1, "yok")})
        op = p.doctrine("özel özet", "digest")
        assert op.stance == "SUPPORTS" and op.confidence == 0.5

    def test_responses_tam_string_eslesme_ister(self):
        """BULGU B4: tam-string eşleşme; beyaz uzay farkı -> default."""
        p = ScriptedProvider(family="fa", identity="fa-1",
                             default=Opinion("SUPPORTS", 0.5, "öntanımlı"),
                             responses={"özet": Opinion("REFUTES", 0.1, "yok")})
        assert p.doctrine("özet ", "d").stance == "SUPPORTS"

    def test_fn_hepsini_gecersiz_kilar(self):
        p = ScriptedProvider(family="fa", identity="fa-1",
                             default=Opinion("SUPPORTS", 0.5, "öntanımlı"),
                             responses={"x": Opinion("REFUTES", 0.1, "yok")},
                             fn=lambda s: Opinion("REFUTES", 0.99, "fn'den"))
        op = p.doctrine("x", "digest")
        assert op.stance == "REFUTES" and op.confidence == 0.99
        # fn responses'taki anahtarı olmayan özet için de çalışır
        assert p.doctrine("hiç yok", "d").stance == "REFUTES"

    def test_digest_ve_sources_argumanlari_gozardi_edilir(self):
        p = _scripted("fa")
        assert p.doctrine("öz", "digest-1", None) == p.doctrine("öz", "digest-2", "kaynak")

    def test_revise_hook_tasinir(self):
        p = _scripted("fa")
        assert p.revise is None
        p2 = ScriptedProvider(family="fa", identity="fa-1",
                              default=Opinion("SUPPORTS", 0.5, "x"),
                              revise=lambda pkt: Opinion("REFUTES", 0.2, "revize"))
        assert p2.revise is not None


# ==================================================== OpenAICompatProvider ===

class TestProviderInit:
    """__init__: açık parametreler ve env öntanımlıları."""

    def test_acik_parametreler(self):
        p = OpenAICompatProvider(family="fa", identity="fa-1",
                                 base_url="http://h:1234/v1",
                                 api_key="sk-123", model="qwen-7b")
        assert p.base_url == "http://h:1234/v1"
        assert p.api_key == "sk-123"
        assert p.model == "qwen-7b"
        assert p.version == "0.1.0"

    def test_env_ontanimlilari(self, monkeypatch):
        monkeypatch.setenv("VERIDICT_JURY_URL", "http://env.local")
        monkeypatch.setenv("VERIDICT_JURY_KEY", "env-anahtar")
        monkeypatch.setenv("VERIDICT_JURY_MODEL", "env-model")
        p = OpenAICompatProvider(family="fa", identity="fa-1")
        assert p.base_url == "http://env.local"
        assert p.api_key == "env-anahtar"
        assert p.model == "env-model"

    def test_url_envi_yoksa_key_error(self, monkeypatch):
        monkeypatch.delenv("VERIDICT_JURY_URL", raising=False)
        with pytest.raises(KeyError):
            OpenAICompatProvider(family="fa", identity="fa-1")

    def test_key_envi_yoksa_bos_string(self, monkeypatch):
        monkeypatch.delenv("VERIDICT_JURY_KEY", raising=False)
        p = OpenAICompatProvider(family="fa", identity="fa-1",
                                 base_url="http://h")
        assert p.api_key == ""

    def test_model_envi_yoksa_gpt_4o_mini(self, monkeypatch):
        monkeypatch.delenv("VERIDICT_JURY_MODEL", raising=False)
        p = OpenAICompatProvider(family="fa", identity="fa-1",
                                 base_url="http://h")
        assert p.model == "gpt-4o-mini"


@pytest.mark.parametrize("env, beklenen", [
    (None, 1),
    ("1", 1),
    ("4", 4),
    ("0", 1),      # max(1, 0)
    ("-3", 1),     # max(1, -3)
    ("abc", 1),    # ValueError yolu
    ("3.0", 1),    # int("3.0") ValueError
])
class TestSamples:
    """_samples: env ayrıştırma dalları (sıra-bağımsız — monkeypatch)."""

    def test_samples_dallari(self, monkeypatch, env, beklenen):
        if env is None:
            monkeypatch.delenv("VERIDICT_JURY_SAMPLES", raising=False)
        else:
            monkeypatch.setenv("VERIDICT_JURY_SAMPLES", env)
        p = OpenAICompatProvider(family="fa", identity="fa-1",
                                 base_url="http://h")
        assert p._samples() == beklenen


@pytest.mark.parametrize("env, n, beklenen", [
    (None, 1, 0.0),
    (None, 2, 0.7),      # örnekleme yapıldığında gerçekten örneklenir
    (None, 5, 0.7),
    ("0.0", 1, 0.0),
    ("0.25", 3, 0.25),   # env n'den bağımsız kazanır
    ("1.0", 1, 1.0),
    ("abc", 1, 0.0),     # çöp env -> yedek
    ("abc", 4, 0.7),     # çöp env & n>1 -> yedek
])
class TestTemperature:
    """_temperature: env / n dalları."""

    def test_temperature_dallari(self, monkeypatch, env, n, beklenen):
        if env is None:
            monkeypatch.delenv("VERIDICT_JURY_TEMPERATURE", raising=False)
        else:
            monkeypatch.setenv("VERIDICT_JURY_TEMPERATURE", env)
        p = OpenAICompatProvider(family="fa", identity="fa-1",
                                 base_url="http://h")
        assert p._temperature(n) == beklenen


@pytest.mark.parametrize("env, beklenen", [
    (None, 60.0),
    ("120", 120.0),
    ("30", 30.0),
    ("5", 10.0),       # max(10, 5) zemin
    ("0", 10.0),
    ("-1", 10.0),
    ("abc", 60.0),     # ValueError yolu
])
class TestTimeout:
    """_timeout: env ayrıştırma + 10s zemin."""

    def test_timeout_dallari(self, monkeypatch, env, beklenen):
        if env is None:
            monkeypatch.delenv("VERIDICT_JURY_TIMEOUT", raising=False)
        else:
            monkeypatch.setenv("VERIDICT_JURY_TIMEOUT", env)
        p = OpenAICompatProvider(family="fa", identity="fa-1",
                                 base_url="http://h")
        assert p._timeout() == beklenen


class TestOneCall:
    """_one / doctrine(n=1): başarı, sözleşme ve taşma başarısızlık dalları."""

    def test_basari_minimal_evidencesiz(self, monkeypatch):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit({"choices": [{"message": {
            "content": json.dumps(_opinion_body())}}]}))
        op = p.doctrine("öz", "dig")
        assert op.stance == "SUPPORTS" and op.confidence == 0.9
        assert op.rationale.endswith(" [no-evidence-field]")

    def test_basari_evidence_alani(self, monkeypatch):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit({"choices": [{"message": {
            "content": json.dumps(
                _opinion_body(evidence=["gözlem bir", "gözlem iki"]))}}]}))
        op = p.doctrine("öz", "dig")
        assert op.rationale.startswith("evidence: gözlem bir; gözlem iki | ")
        assert "[no-evidence-field]" not in op.rationale

    @pytest.mark.parametrize("ev", [
        "düz-string",              # liste değil
        ["tek"],                   # len < 2
        ["dolu", "   "],           # boş string öğesi
        ["dolu", 7],               # string dışı öğe
        [],
    ])
    def test_kotu_evidence_provider_error(self, monkeypatch, ev):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit({"choices": [{"message": {
            "content": json.dumps(_opinion_body(evidence=ev))}}]}))
        with pytest.raises(ProviderError):
            p.doctrine("öz", "dig")

    @pytest.mark.parametrize("stance", ["MAYBE", "supports", "ABSTAIN", ""])
    def test_kotu_stance_provider_error(self, monkeypatch, stance):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit({"choices": [{"message": {
            "content": json.dumps(_opinion_body(stance=stance))}}]}))
        with pytest.raises(ProviderError):
            p.doctrine("öz", "dig")

    @pytest.mark.parametrize("stance", ["SUPPORTS", "REFUTES"])
    def test_gecerli_stance_lar(self, monkeypatch, stance):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit({"choices": [{"message": {
            "content": json.dumps(_opinion_body(stance=stance))}}]}))
        assert p.doctrine("öz", "dig").stance == stance

    def test_confidence_string_floata(self, monkeypatch):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit({"choices": [{"message": {
            "content": json.dumps(_opinion_body(confidence="0.42"))}}]}))
        assert p.doctrine("öz", "dig").confidence == pytest.approx(0.42)

    def test_rationale_str_e_zorlanir(self, monkeypatch):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit({"choices": [{"message": {
            "content": json.dumps(_opinion_body(rationale=123))}}]}))
        assert p.doctrine("öz", "dig").rationale == "123 [no-evidence-field]"

    def test_http_hata_durumu_provider_error(self, monkeypatch):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit(status_code=500))
        with pytest.raises(ProviderError):
            p.doctrine("öz", "dig")

    def test_transport_hatasi_provider_error(self, monkeypatch):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, httpx.ConnectError("bağlantı yok"))
        with pytest.raises(ProviderError):
            p.doctrine("öz", "dig")

    def test_bozuk_json_provider_error(self, monkeypatch):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit,
                      _Yanit({"choices": [{"message": {"content": "{bad json"}}]}))
        with pytest.raises(ProviderError):
            p.doctrine("öz", "dig")

    @pytest.mark.parametrize("body", [
        {},                                   # choices yok
        {"choices": []},                      # [0] yok
        {"choices": [{"role": "user"}]},      # message yok
        {"choices": [{"message": {}}]},       # content yok
        {"choices": [{"message": {"content": "{}"}}]},  # stance yok
    ])
    def test_eksik_anahtar_provider_error(self, monkeypatch, body):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit(body))
        with pytest.raises(ProviderError):
            p.doctrine("öz", "dig")

    def test_api_key_yoksa_baslik_yok(self, monkeypatch):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit({"choices": [{"message": {
            "content": json.dumps(_opinion_body())}}]}), api_key="")
        p.doctrine("öz", "dig")
        assert kayit["caglar"][0]["headers"] == {}

    def test_api_key_varsa_bearer_basligi(self, monkeypatch):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit({"choices": [{"message": {
            "content": json.dumps(_opinion_body())}}]}), api_key="sk-x")
        p.doctrine("öz", "dig")
        assert kayit["caglar"][0]["headers"] == {"Authorization": "Bearer sk-x"}

    def test_url_eklemi_ve_payload(self, monkeypatch):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit({"choices": [{"message": {
            "content": json.dumps(_opinion_body())}}]}), model="qwen-7b")
        p.doctrine("öz", "dig")
        c = kayit["caglar"][0]
        # trailing slash kırpılır + endpoint eklenir
        assert c["url"] == "http://mock.local/chat/completions"
        assert c["json"]["model"] == "qwen-7b"
        assert c["json"]["temperature"] == 0.0     # n=1
        assert c["json"]["messages"][0]["role"] == "user"

    def test_prompt_claim_ve_digest_icerir(self, monkeypatch):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit({"choices": [{"message": {
            "content": json.dumps(_opinion_body())}}]}))
        p.doctrine("özET-1", "DİGEST-9")
        prompt = kayit["caglar"][0]["json"]["messages"][0]["content"]
        assert "özET-1" in prompt and "DİGEST-9" in prompt
        assert "Artifact source" not in prompt

    def test_sources_varsa_prompt_kaynak_blokunu_icerir(self, monkeypatch):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit({"choices": [{"message": {
            "content": json.dumps(_opinion_body())}}]}))
        p.doctrine("öz", "dig", sources="--- a.py ---\nx = 1")
        prompt = kayit["caglar"][0]["json"]["messages"][0]["content"]
        assert "Artifact source" in prompt
        assert "--- a.py ---\nx = 1" in prompt

    def test_beklenen_imza_gecirilir(self, monkeypatch):
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, _Yanit({"choices": [{"message": {
            "content": json.dumps(_opinion_body())}}]}))
        p.doctrine("öz", "dig")
        assert kayit["caglar"][0]["timeout"] == 60.0


class TestSampleCalibration:
    """doctrine(n>1): çoğunluk / çoğunluk yok / oybirliği + BULGU B2."""

    def test_cogunluk_conf_ve_not(self, monkeypatch):
        monkeypatch.setenv("VERIDICT_JURY_SAMPLES", "3")
        yanitlar = [
            _Yanit({"choices": [{"message": {"content": json.dumps(
                _opinion_body(stance="SUPPORTS", confidence=0.9))}}]}),
            _Yanit({"choices": [{"message": {"content": json.dumps(
                _opinion_body(stance="REFUTES", confidence=0.7))}}]}),
            _Yanit({"choices": [{"message": {"content": json.dumps(
                _opinion_body(stance="SUPPORTS", confidence=0.6))}}]}),
        ]
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, lambda i: yanitlar[i])
        op = p.doctrine("öz", "dig")
        assert op.stance == "SUPPORTS"
        # conf = mean(0.9, 0.6) * (2/3)
        assert op.confidence == pytest.approx(0.75 * 2 / 3)
        assert op.rationale.endswith(" [sample-calibration: 2/3 SUPPORTS]")
        assert len(kayit["caglar"]) == 3

    def test_cogunluk_yoksa_provider_error(self, monkeypatch):
        monkeypatch.setenv("VERIDICT_JURY_SAMPLES", "4")
        yanitlar = [_Yanit({"choices": [{"message": {"content": json.dumps(
            _opinion_body(stance=s, confidence=0.5))}}]})
            for s in ("SUPPORTS", "REFUTES", "SUPPORTS", "REFUTES")]
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, lambda i: yanitlar[i])
        with pytest.raises(ProviderError, match="sample-split"):
            p.doctrine("öz", "dig")

    def test_oybirlikte_agree_1(self, monkeypatch):
        monkeypatch.setenv("VERIDICT_JURY_SAMPLES", "2")
        yanitlar = [_Yanit({"choices": [{"message": {"content": json.dumps(
            _opinion_body(stance="REFUTES", confidence=0.4))}}]})
            for _ in range(2)]
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, lambda i: yanitlar[i])
        op = p.doctrine("öz", "dig")
        assert op.stance == "REFUTES"
        assert op.confidence == pytest.approx(0.4)
        assert op.rationale.endswith(" [sample-calibration: 2/2 REFUTES]")

    def test_iki_ornekte_bolunmus_provider_error(self, monkeypatch):
        monkeypatch.setenv("VERIDICT_JURY_SAMPLES", "2")
        yanitlar = [_Yanit({"choices": [{"message": {"content": json.dumps(
            _opinion_body(stance=s, confidence=0.5))}}]})
            for s in ("SUPPORTS", "REFUTES")]
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, lambda i: yanitlar[i])
        with pytest.raises(ProviderError, match="sample-split"):
            p.doctrine("öz", "dig")

    def test_temperature_07_gonderilir(self, monkeypatch):
        monkeypatch.setenv("VERIDICT_JURY_SAMPLES", "2")
        monkeypatch.delenv("VERIDICT_JURY_TEMPERATURE", raising=False)
        yanitlar = [_Yanit({"choices": [{"message": {"content": json.dumps(
            _opinion_body())}}]}) for _ in range(2)]
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, lambda i: yanitlar[i])
        p.doctrine("öz", "dig")
        assert kayit["caglar"][0]["json"]["temperature"] == 0.7

    def test_tek_bozuk_ornek_yalitilir_kosu_devam_eder(self, monkeypatch):
        """BULGU B2 (DÜZELTİLDİ VERIDICT-JURY-B2): örnek başına yalıtım —
        tek bozuk örnek atılır (çekimser/notr), sağlam örnekler oylanır ve
        doktrin çağrısı ARTIK düşmez."""
        monkeypatch.setenv("VERIDICT_JURY_SAMPLES", "3")
        yanitlar = [_Yanit({"choices": [{"message": {"content": json.dumps(
            _opinion_body())}}]}),
            _Yanit({"choices": [{"message": {"content": json.dumps(
                _opinion_body(stance="MAYBE"))}}]}),
            _Yanit({"choices": [{"message": {"content": json.dumps(
                _opinion_body())}}]})]
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, lambda i: yanitlar[i])
        op = p.doctrine("öz", "dig")
        assert len(kayit["caglar"]) == 3            # 2. örnekte DURMADI
        assert op.stance == "SUPPORTS"
        assert op.confidence == pytest.approx(0.9)   # mean(0.9, 0.9) * (2/2)
        assert " [1/3 sample-failed]" in op.rationale
        assert op.rationale.endswith(" [sample-calibration: 2/2 SUPPORTS]")

    def test_bozuk_ornek_sayilir_istenen_toplam_ornege_kayit_duser(
            self, monkeypatch):
        """Dürüstlük kaydı: atılan örnek receipt'te görünür (kullanılabilir
        örnek < istenen örnek)."""
        monkeypatch.setenv("VERIDICT_JURY_SAMPLES", "4")
        iyi = _Yanit({"choices": [{"message": {"content": json.dumps(
            _opinion_body(stance="REFUTES", confidence=0.5))}}]})
        kotu = _Yanit({"choices": [{"message": {"content": json.dumps(
            _opinion_body(stance="KÖKÜ")
        )}}]})
        yanitlar = [iyi, kotu, iyi, iyi]
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, lambda i: yanitlar[i])
        op = p.doctrine("öz", "dig")
        assert op.stance == "REFUTES"
        assert " [1/4 sample-failed]" in op.rationale
        assert op.rationale.endswith(" [sample-calibration: 3/3 REFUTES]")
        assert len(kayit["caglar"]) == 4

    def test_transport_hatasi_olan_ornek_de_yalitilir(self, monkeypatch):
        """Bozuk örnek yalnızca bozuk-GÖVDE değil, bozuk-ULAŞIM da olabilir:
        _one'ın ProviderError'ı yakalanır, koşu devam eder."""
        monkeypatch.setenv("VERIDICT_JURY_SAMPLES", "3")
        iyi = _Yanit({"choices": [{"message": {"content": json.dumps(
            _opinion_body(confidence=0.8))}}]})

        def yanit(i):
            if i == 1:
                raise httpx.ConnectError("endpoint öldü")
            return iyi

        kayit: dict = {}
        p = _provider(monkeypatch, kayit, yanit)
        op = p.doctrine("öz", "dig")
        assert op.stance == "SUPPORTS" and op.confidence == pytest.approx(0.8)
        assert " [1/3 sample-failed]" in op.rationale

    def test_bozuk_ornek_sonrasi_bolunme_yine_provider_error(
            self, monkeypatch):
        """Yalıtım çoğunluk uydurmaz: atılan örnekten sonra kalanlar
        bölünmüşse sample-split ile yine çekimser."""
        monkeypatch.setenv("VERIDICT_JURY_SAMPLES", "3")
        yanitlar = [_Yanit({"choices": [{"message": {"content": json.dumps(
            _opinion_body(stance="SUPPORTS"))}}]}),
            _Yanit({"choices": [{"message": {"content": json.dumps(
                _opinion_body(stance="MAYBE"))}}]}),
            _Yanit({"choices": [{"message": {"content": json.dumps(
                _opinion_body(stance="REFUTES"))}}]})]
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, lambda i: yanitlar[i])
        with pytest.raises(ProviderError, match="sample-split"):
            p.doctrine("öz", "dig")
        assert len(kayit["caglar"]) == 3

    def test_tum_ornekler_bozuksa_cekimser(self, monkeypatch):
        """Fail-closed taban: kullanılabilir örnek hiç yoksa jüri çekimser
        kalır (ProviderError), boş çoğunluk uydurulmaz."""
        monkeypatch.setenv("VERIDICT_JURY_SAMPLES", "3")
        yanitlar = [_Yanit({"choices": [{"message": {"content": json.dumps(
            _opinion_body(stance="MAYBE"))}}]}) for _ in range(3)]
        kayit: dict = {}
        p = _provider(monkeypatch, kayit, lambda i: yanitlar[i])
        with pytest.raises(ProviderError, match="all 3 samples failed"):
            p.doctrine("öz", "dig")
        assert len(kayit["caglar"]) == 3        # hepsi denendi


# ============================================================== Jury.init ====

class TestJuryInit:
    """Jury.__init__: aile/çokluk doğrulama + self-preference dışlama."""

    def test_iki_saglayici_iki_aila_ok(self):
        j = _iki_juri()
        assert len(j.providers) == 2
        assert j.excluded == []

    def test_tek_saglayici_value_error(self):
        with pytest.raises(ValueError, match="§5.2"):
            Jury([_scripted("fa")])

    def test_sifir_saglayici_value_error(self):
        with pytest.raises(ValueError):
            Jury([])

    def test_iki_saglayici_ayni_aila_value_error(self):
        with pytest.raises(ValueError, match="distinct families"):
            Jury([_scripted("fa", "a"), _scripted("fa", "b")])

    def test_uc_saglayici_iki_aila_ok(self):
        j = Jury([_scripted("fa", "a"), _scripted("fa", "b"), _scripted("fb")])
        assert len(j.providers) == 3

    @pytest.mark.parametrize("author, dislanan", [
        ("fa", 1),
        ("  FA  ", 1),      # büyük-küçük + beyaz-uzay duyarsız
        ("FA", 1),
        ("yok", 0),
        ("", 0),
    ])
    def test_author_family_dislama(self, author, dislanan):
        j = Jury([_scripted("fa"), _scripted("fb"), _scripted("fc")],
                 author_family=author)
        assert len(j.excluded) == dislanan
        assert len(j.providers) == 3 - dislanan

    def test_author_family_none_dislama_yok(self):
        j = Jury([_scripted("fa"), _scripted("fb")], author_family=None)
        assert j.excluded == [] and len(j.providers) == 2

    def test_author_family_hepsini_dislar_value_error(self):
        with pytest.raises(ValueError, match="§5.2"):
            Jury([_scripted("fa", "a"), _scripted("fa", "b")],
                 author_family="fa")

    def test_author_family_birini_dislar_geri_kalan_gecerli(self):
        j = Jury([_scripted("fa", "fa-1"), _scripted("fa", "fa-2"),
                  _scripted("fb"), _scripted("fc")], author_family="fa")
        assert len(j.excluded) == 2
        assert len(j.providers) == 2
        assert {p.identity for p in j.providers} == {"fb-1", "fc-1"}
        # dışlama sonrası <2 sağlayıcı kalırsa fail-closed ValueError
        with pytest.raises(ValueError):
            Jury([_scripted("fa", "fa-1"), _scripted("fb")],
                 author_family="fa")

    def test_saglayici_family_beyaz_uzayli(self):
        j = Jury([_scripted("  Fa "), _scripted("fb"), _scripted("fc")],
                 author_family="fa")
        assert len(j.excluded) == 1
        assert len(j.providers) == 2
        assert {p.family for p in j.providers} == {"fb", "fc"}


# =========================================================== Jury.evaluate ===

class TestJuryEvaluate:
    """evaluate: başarı / çekimser / kanıt kimliği / kaynak dalları."""

    def test_hepsi_basarili_iki_ogesi(self):
        items, abstained = _iki_juri().evaluate(_claim(), "dig")
        assert abstained == []
        assert len(items) == 2

    def test_oge_alanlari(self):
        items, _ = _iki_juri().evaluate(_claim(), "dig-7")
        for it in items:
            assert it.tier == "W2"
            assert it.evidence_class == "JURY_OPINION"
            assert it.artifact_ref == "dig-7"
            assert it.claim_id == "c1"
            assert it.reproducibility == {"deterministic": False,
                                          "rerun_recipe": None}
            assert it.producer["kind"] == "jury"
            assert it.producer["family"] in ("fa", "fb")
            assert it.producer["version"] == "0.1.0"

    def test_evidence_id_deterministik(self):
        def beklenen(identity):
            return sha256_hex(f"{EID_SALT}|c1|{identity}")[:24]
        items1, _ = _iki_juri().evaluate(_claim(), "dig")
        items2, _ = _iki_juri().evaluate(_claim(), "dig")
        ids1 = {it.evidence_id for it in items1}
        assert ids1 == {beklenen("fa-1"), beklenen("fb-1")}
        assert ids1 == {it.evidence_id for it in items2}

    def test_evidence_id_claim_ve_identity_gore_degisir(self):
        a, _ = _iki_juri().evaluate(_claim("c1"), "dig")
        b, _ = _iki_juri().evaluate(_claim("c2"), "dig")
        assert {it.evidence_id for it in a} != {it.evidence_id for it in b}

    def test_bir_saglayici_provider_error_cekimser(self):
        class Boom(ScriptedProvider):
            def doctrine(self, claim_summary, artifact_digest, sources=None):
                raise ProviderError("kesinti")

        j = Jury([Boom(family="boom", identity="boom-1",
                       default=Opinion("SUPPORTS", 0.5, "")),
                  _scripted("fb")])
        items, abstained = j.evaluate(_claim(), "dig")
        assert len(items) == 1
        assert abstained == ["boom-1"]
        assert items[0].producer["identity"] == "fb-1"

    def test_provider_error_disi_istisna_yayilir(self):
        class Boom(ScriptedProvider):
            def doctrine(self, claim_summary, artifact_digest, sources=None):
                raise RuntimeError("beklenmeyen")

        j = Jury([Boom(family="boom", identity="boom-1",
                       default=Opinion("SUPPORTS", 0.5, "")),
                  _scripted("fb")])
        with pytest.raises(RuntimeError):
            j.evaluate(_claim(), "dig")

    def test_artifact_dir_yoksa_sources_none(self):
        goruldu = []

        class Spike(ScriptedProvider):
            def doctrine(self, claim_summary, artifact_digest, sources=None):
                goruldu.append(sources)
                return Opinion("SUPPORTS", 0.5, "x")

        Jury([Spike(family="fa", identity="fa-1",
                    default=Opinion("SUPPORTS", 0.5, "x")),
              Spike(family="fb", identity="fb-1",
                    default=Opinion("SUPPORTS", 0.5, "x"))
              ]).evaluate(_claim(), "dig")
        assert goruldu == [None, None]

    def test_artifact_dir_doluysa_sources_dolu(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1", encoding="utf-8")
        goruldu = []

        class Spike(ScriptedProvider):
            def doctrine(self, claim_summary, artifact_digest, sources=None):
                goruldu.append(sources)
                return Opinion("SUPPORTS", 0.5, "x")

        Jury([Spike(family="fa", identity="fa-1",
                    default=Opinion("SUPPORTS", 0.5, "x")),
              Spike(family="fb", identity="fb-1",
                    default=Opinion("SUPPORTS", 0.5, "x"))
              ]).evaluate(_claim(), "dig", str(tmp_path))
        assert len(goruldu) == 2
        for s in goruldu:
            assert s is not None and "a.py" in s and "x = 1" in s

    def test_artifact_dir_kaynak_yoksa_sources_none(self, tmp_path):
        goruldu = []

        class Spike(ScriptedProvider):
            def doctrine(self, claim_summary, artifact_digest, sources=None):
                goruldu.append(sources)
                return Opinion("SUPPORTS", 0.5, "x")

        Jury([Spike(family="fa", identity="fa-1",
                    default=Opinion("SUPPORTS", 0.5, "x")),
              Spike(family="fb", identity="fb-1",
                    default=Opinion("SUPPORTS", 0.5, "x"))
              ]).evaluate(_claim(), "dig", str(tmp_path))
        assert goruldu == [None, None]

    def test_dislanan_self_preference_notuyla(self):
        j = Jury([_scripted("fa", "fa-1"), _scripted("fb"), _scripted("fc")],
                 author_family="fa")
        items, abstained = j.evaluate(_claim(), "dig")
        # dışlanan fa-1 çekimser; geri kalan iki jüri üyesi oy verir
        assert len(items) == 2
        assert {it.producer["identity"] for it in items} == {"fb-1", "fc-1"}
        assert abstained == ["fa-1 (self-preference: author family 'fa')"]

    def test_dislanan_ve_cekimser_birlikte(self):
        class Boom(ScriptedProvider):
            def doctrine(self, claim_summary, artifact_digest, sources=None):
                raise ProviderError("kesinti")

        j = Jury([_scripted("fa", "fa-1"),
                  Boom(family="fb", identity="fb-1",
                       default=Opinion("SUPPORTS", 0.5, "")),
                  _scripted("fc", "fc-1")], author_family="fa")
        items, abstained = j.evaluate(_claim(), "dig")
        assert len(items) == 1
        assert abstained == [
            "fa-1 (self-preference: author family 'fa')", "fb-1"]


# ============================================================ _build_item ====

class TestBuildItem:
    """_build_item: tuz/üretici dalları."""

    def test_round_salt_evidence_id_degistirir(self):
        j = _iki_juri()
        p = j.providers[0]
        claim, op = _claim(), Opinion("SUPPORTS", 0.8, "neden")
        a = j._build_item(claim, "dig", p, op)
        b = j._build_item(claim, "dig", p, op, round_salt="özel-tuz")
        assert a.evidence_id != b.evidence_id
        assert b.evidence_id == sha256_hex(f"özel-tuz|c1|fa-1")[:24]

    def test_uretici_family_tasiyor(self):
        j = _iki_juri()
        it = j._build_item(_claim(), "dig", j.providers[0],
                           Opinion("REFUTES", 0.3, "neden"))
        assert it.producer == {"kind": "jury", "identity": "fa-1",
                               "version": "0.1.0", "family": "fa"}
        assert it.stance == "REFUTES" and it.confidence == 0.3
        assert it.rationale == "neden"


# =========================================================== Jury.deliberate ==

class TestJuryDeliberate:
    """deliberate: revizyon / hata düşüşü / packet / eksik öğe dalları."""

    def _ilkeler(self, jury, duruş="SUPPORTS", conf=0.8):
        return jury._build_item(_claim(), "dig", jury.providers[0],
                                Opinion(duruş, conf, "ilk görüş"))

    def test_revise_hook_yoksa_ilk_gorugu_korur(self):
        j = _iki_juri()
        first = self._ilkeler(j)
        revised, abstained = j.deliberate(_claim(), "dig", [first])
        # yalnızca fa-1'in first-round öğesi var; fb-1'in yok -> çekimser
        assert abstained == ["fb-1"]
        assert len(revised) == 1
        r = revised[0]
        assert r.stance == "SUPPORTS" and r.confidence == 0.8
        assert r.rationale == "ilk görüş"
        # ama tuz değiştiği için kimlik farklı
        assert r.evidence_id != first.evidence_id
        assert r.evidence_id == sha256_hex(f"{EID_SALT}-r2|c1|fa-1")[:24]

    def test_revise_hook_varsa_revize_gorus(self):
        def revise(packets):
            return Opinion("REFUTES", 0.2, "revize edildi")

        j = Jury([ScriptedProvider(family="fa", identity="fa-1",
                                   default=Opinion("SUPPORTS", 0.8, "ilk"),
                                   revise=revise),
                  _scripted("fb")])
        first = self._ilkeler(j)
        revised, abstained = j.deliberate(_claim(), "dig", [first])
        assert revised[0].stance == "REFUTES"
        assert revised[0].confidence == 0.2
        assert revised[0].rationale == "revize edildi"

    def test_revise_hook_hata_verirse_ilk_gorugu_korur(self):
        def revise(packets):
            raise RuntimeError("kanca çöktü")

        j = Jury([ScriptedProvider(family="fa", identity="fa-1",
                                   default=Opinion("SUPPORTS", 0.8, "ilk"),
                                   revise=revise),
                  _scripted("fb")])
        first = self._ilkeler(j, duruş="REFUTES")
        revised, _ = j.deliberate(_claim(), "dig", [first])
        # fail-open değil: ilk REFUTES korunur (silinmez)
        assert revised[0].stance == "REFUTES"
        assert revised[0].rationale == "ilk görüş"

    def test_packet_kendini_dislar(self):
        goruldu = []

        def revise(packets):
            # deliberate bu sağlayıcıya DİĞERLERİNİN packet listesini verir
            goruldu.append(packets)
            return Opinion("SUPPORTS", 0.5, "revize")

        j = Jury([ScriptedProvider(family="fa", identity="fa-1",
                                   default=Opinion("SUPPORTS", 0.8, "ilk"),
                                   revise=revise),
                  ScriptedProvider(family="fb", identity="fb-1",
                                   default=Opinion("REFUTES", 0.7, "ilk2"),
                                   revise=revise)])
        first = [j._build_item(_claim(), "dig", p,
                               Opinion("SUPPORTS", 0.8, "ilk görüş"))
                 for p in j.providers]
        j.deliberate(_claim(), "dig", first)
        # her sağlayıcı sadece DİĞERİNİN packet'ını görür (kördür)
        assert goruldu[0] == [{"identity": "fb-1", "family": "fb",
                               "stance": "SUPPORTS", "confidence": 0.8,
                               "rationale": ""}]
        assert goruldu[1] == [{"identity": "fa-1", "family": "fa",
                               "stance": "SUPPORTS", "confidence": 0.8,
                               "rationale": ""}]

    def test_ilk_ogesi_olmayan_cekimser(self):
        j = _iki_juri()
        # sadece fa-1'in first-round öğesi var
        first = [self._ilkeler(j)]
        revised, abstained = j.deliberate(_claim(), "dig", first)
        assert len(revised) == 1
        assert abstained == ["fb-1"]

    def test_tolerance_parametresi_kaldirildi(self):
        """BULGU B1 (DÜZELTİLDİ VERIDICT-JURY-B1): `tolerance` ölü
        parametreydi (hiçbir dal okumuyordu) — KALDIRILDI. Eski 4-konumlu
        çağrı artık sessiz-kabul değil gürültülü TypeError verir."""
        import inspect
        beklenen = ["self", "claim", "artifact_digest", "first_items"]
        assert list(inspect.signature(Jury.deliberate).parameters) == beklenen
        assert "tolerance" not in inspect.signature(
            Jury.deliberate).parameters

    def test_eski_tolerance_argumanı_gorulekli_red(self):
        """Fail-closed: politika eşiğini revizyona geçiriyormuş gibi yapan
        eski çağrı biçimi artık kabul edilmez (ölü argüman sessizce
        yutılmaz)."""
        j = _iki_juri()
        first = self._ilkeler(j)
        with pytest.raises(TypeError):
            j.deliberate(_claim(), "dig", [first], 0.3)

    def test_turde_gore_sonuc_degismez(self):
        """B1 sonrası korunan gözlem: revizyon turu sapma eşiğinden bağımsız
        (eşik compute_divergence/adjudicate tarafında uygulanıyor)."""
        j = _iki_juri()
        first = self._ilkeler(j)
        a, _ = j.deliberate(_claim(), "dig", [first])
        b, _ = j.deliberate(_claim(), "dig", [first])
        assert a[0].evidence_id == b[0].evidence_id
        assert a[0].stance == b[0].stance

    def test_coklu_saglayicinin_hepsinde_oge_varsa(self):
        j = _iki_juri()
        first = [j._build_item(_claim(), "dig", p,
                               Opinion("SUPPORTS", 0.8, "ilk görüş"))
                 for p in j.providers]
        revised, abstained = j.deliberate(_claim(), "dig", first)
        assert abstained == []
        assert len(revised) == 2
        assert {r.producer["identity"] for r in revised} == {"fa-1", "fb-1"}
