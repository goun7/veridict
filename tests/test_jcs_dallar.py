"""Veridict tamga_anchor RFC 8785 (JCS) dal-kesen testleri (LEED).

Kural-1: MEVCUT DOSYALARA DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (str/siralama/kacis-hesabi — dis cagri YOK).
_jcs + _jcs_str: ECMAScript-safe-int siniri, float REDDI, bool-önceliği,
UTF-16 code-unit siralamasi, astral surrogate-pair, kacis-tablosu.
"""
import sys

import pytest

sys.path.insert(0, ".")
from veridict.tamga_anchor import _jcs, _jcs_str  # noqa: E402


# == _jcs: skaler tipler ========================================================================

@pytest.mark.parametrize("value,expected", [
    (None, "null"),
    (True, "true"),
    (False, "false"),
    (0, "0"),
    (1, "1"),
    (-1, "-1"),
    (42, "42"),
    (9007199254740991, "9007199254740991"),          # 2**53 - 1 (sinir-dahil)
    (-9007199254740991, "-9007199254740991"),        # negatif sinir-dahil
])
def test_skaler(value, expected):
    """ORTAM: None/bool/int skaler dogru serilesir; bool int'ten ÖNCE ele alinir."""
    assert _jcs(value) == expected


@pytest.mark.parametrize("value", [
    9007199254740992,        # 2**53 (sinir-disi)
    9007199254740993,        # 2**53 + 1
    -9007199254740992,       # -2**53
    -9007199254740993,       # -2**53 - 1
    10**30,
    -(10**30),
])
def test_güvensiz_tamsayi_reddi(value):
    """ORTAM-OGRENDI: ECMAScript safe-int siniri 2**53; ASIRILIRSA ValueError.
    abs() kullanildigi icin pozitif/negatif simetrik. RFC 8785 §3.2.2.2."""
    with pytest.raises(ValueError, match="safe-integer"):
        _jcs(value)


@pytest.mark.parametrize("value", [
    1.0,
    0.5,
    -0.25,
    3.14,
    0.0,
    float("nan"),
    float("inf"),
    float("-inf"),
])
def test_float_reddi(value):
    """ORTAM-OGRENDI: floatlar ASLA serilesmez — ECMAScript number-formatlama
    implemente edilmedigi icin dil-bozucu hash-paritesi bozulur. NaN/Infinity
    dahil her float ValueError. (tamga_canon sapmasi, dis denetmen bulgusu)."""
    with pytest.raises(ValueError, match="floats are rejected"):
        _jcs(value)


@pytest.mark.parametrize("value,exc", [
    (b"x", TypeError),
    (bytearray(b"x"), TypeError),
    ({1, 2}, TypeError),
    (frozenset({1}), TypeError),
    (object(), TypeError),
    (complex(1, 2), TypeError),
])
def test_desteklenmeyen_tip(value, exc):
    """ORTAM: bytes/set/object/complex → TypeError (fail-closed, sessiz serilesme YOK)."""
    with pytest.raises(exc, match="unsupported type"):
        _jcs(value)


def test_bool_int_alt_sinifi_ayrimi():
    """ORTAM-OGRENDI: bool int'in alt-sinifidir ama True/False once yakalanir;
    liste icinde de boyle — [true,false,null], ['1'] DEGIL."""
    assert _jcs([True, False, None]) == "[true,false,null]"
    assert _jcs({"x": True, "y": False}) == '{"x":true,"y":false}'


# == _jcs_str: kacis-tablosu =====================================================================

@pytest.mark.parametrize("char,expected", [
    ("\\", '"\\\\"'),        # backslash — cift
    ('"', '"\\""'),          # tirnak
    ("\b", '"\\b"'),         # backspace
    ("\f", '"\\f"'),         # form feed
    ("\n", '"\\n"'),         # newline
    ("\r", '"\\r"'),         # carriage return
    ("\t", '"\\t"'),         # tab
])
def test_kacis_tablosu(char, expected):
    """ORTAM: _ESCAPE tablosu 7-karakter; RFC 8785 kisa-kacislari kullaniir."""
    assert _jcs_str(char) == expected


@pytest.mark.parametrize("code,expected", [
    (0x00, '"\\u0000"'),
    (0x01, '"\\u0001"'),
    (0x07, '"\\u0007"'),     # bell — tabloda YOK, \u yolu
    (0x1F, '"\\u001f"'),     # unit separator — sinir-sonu
])
def test_kontrol_karakteri(code, expected):
    """ORTAM: 0x00-0x1F araligi (0x20 haric) \\uXXXX kucuk-hex ile serilesir."""
    assert _jcs_str(chr(code)) == expected


@pytest.mark.parametrize("char,expected", [
    ("a", '"a"'),
    ("Z", '"Z"'),
    ("0", '"0"'),
    ("~", '"~"'),            # 0x7E
    ("\x7f", '"\x7f"'),      # 0x7F DEL — ASCII-dogrudan (0x80 altinda)
    (" ", '" "'),            # bosluk 0x20 — kacis YOK
    ("/", '"/"'),
])
def test_ascii_dogrudan(char, expected):
    """ORTAM: 0x20-0x7F araligi dokunulmadan yazilir (0x7f DAHIL)."""
    assert _jcs_str(char) == expected


@pytest.mark.parametrize("char,expected", [
    ("\x80", '"\\u0080"'),       # Latin-1 baslangici
    ("\xff", '"\\u00ff"'),
    ("é", '"\\u00e9"'),          # U+00E9
    ("ñ", '"\\u00f1"'),
    ("\u07ff", '"\\u07ff"'),     # BMP sonuna yakin
])
def test_bmp_ascii_disi(char, expected):
    """ORTAM: 0x80-0xFFFF BMP araligi \\uXXXX (4-hex, kucuk)."""
    assert _jcs_str(char) == expected


@pytest.mark.parametrize("char,expected", [
    ("😀", '"\\ud83d\\ude00"'),          # U+1F600
    ("𝟸", '"\\ud835\\udff8"'),           # U+1D7F8 math digit
    ("𝄞", '"\\ud834\\udd1e"'),           # U+1D11E musical G clef
    ("𐍈", '"\\ud800\\udf48"'),           # U+10348
])
def test_astral_surrogate_pair(char, expected):
    r"""ORTAM-OGRENDI: U+10000+ astral-duzlem karakterleri UTF-16 SURROGATE
    PAIR'e donusur (high D800-DBFF + low DC00-DFFF). Python str ord() > 0xFFFF
    kontrolu bunu belirler — tek backslash-u ile tek-basamak YANLIS olurdu."""
    assert _jcs_str(char) == expected


def test_birlesik_kacis_serisi():
    """ORTAM: kacis-tablosu + ASCII karisik ayni stringde dogru calisir."""
    assert _jcs_str("a\rb\"c\td") == '"a\\rb\\"c\\td"'


def test_bos_string():
    assert _jcs_str("") == '""'


def test_string_jcs_ile_uyumlu():
    """ORTAM: _jcs(str) _jcs_str(str) ile ayni ciktiyi verir."""
    for s in ["", "a", "x\ty", "é", "😀", "quote\"and\\slash"]:
        assert _jcs(s) == _jcs_str(s)


def test_normalestirme_yok():
    """ORTAM-OGRENDI: 'é' (U+00E9 tek-basamak) ile 'e´' (U+0065+U+0301) FARKLI
    serilesir — Unicode-normalestirme YAPILMAZ, kod-noktalari birebir saklanir.
    Bu hash-paritesi icin kritik: normallestirme kanali RFC 8785 disinda."""
    assert _jcs_str("é") != _jcs_str("e\u0301")
    assert _jcs_str("e\u0301") == '"e\\u0301"'


# == _jcs: konteyner siralama (RFC 8785 §3.2.3) ==================================================

@pytest.mark.parametrize("obj,expected", [
    ({}, "{}"),
    ({}, "{}"),
    ({"a": 1}, '{"a":1}'),
    ({"b": 1, "a": 2}, '{"a":2,"b":1}'),                    # alfabe-sirali
    ({"Z": 3, "a": 2, "b": 1}, '{"Z":3,"a":2,"b":1}'),      # ASCII buyuk-once
    ({"a": 1, "A": 2, "_": 3, "0": 4},
     '{"0":4,"A":2,"_":3,"a":1}'),                          # 0 < A < _ < a
])
def test_dict_siralama(obj, expected):
    """ORTAM: dict member'lari UTF-16 code-unit sirasina gore (sorted())."""
    assert _jcs(obj) == expected


def test_utf16_code_unit_siralamasi():
    """ORTAM-OGRENDI: siralama UTF-16 code-unit uzerindendir — 'z' (0x007A)
    'é' (0x00E9) dan ÖNCE gelir; saf codepoint siralasaydi yine ayni burada
    ama alt-cergeve ascii-mixed anahtarlarla kesinlesir."""
    out = _jcs({"z": 1, "é": 2, "A": 3, "_": 4})
    assert out == '{"A":3,"_":4,"z":1,"\\u00e9":2}'


def test_icice_dict_siralama():
    """ORTAM: siralama her seviyede ozyineli uygulanir."""
    assert _jcs({"a": {"c": 1, "b": 2}}) == '{"a":{"b":2,"c":1}}'


def test_dict_anahtari_astral():
    """ORTAM: astral anahtarlar surrogate-pair olarak siralanir."""
    assert _jcs({"\U0001D7D8": 1}) == '{"\\ud835\\udfd8":1}'


@pytest.mark.parametrize("keys", [
    {1: "x"},
    {(1, 2): "x"},
    {None: "x"},
    {True: "x"},
    {3.14: "x"},
    {b"k": "x"},
])
def test_dizisel_olmayan_anahtar_reddi(keys):
    """ORTAM: int/tuple/None/bool/float/bytes anahtarlar ValueError —
    bunlar gecerli JSON degil, sessiz str() cevirisi YAPILMAZ."""
    with pytest.raises(ValueError, match="non-string object keys"):
        _jcs(keys)


@pytest.mark.parametrize("obj,expected", [
    ([], "[]"),
    ([1, 2, 3], "[1,2,3]"),
    (["a", "b"], '["a","b"]'),
    ((1, 2), "[1,2]"),                 # tuple — liste ile ayni cikti
    ((), "[]"),
    ([None, True, False], "[null,true,false]"),
    ([[1, 2], [3]], "[[1,2],[3]]"),    # icice listeler
    ([{"b": 1, "a": 2}], '[{"a":2,"b":1}]'),   # listede dict siralanir
])
def test_liste(obj, expected):
    """ORTAM: liste/tuple ayni ciktiyi verir; ayirac YOK, ozyineli siralama dahil."""
    assert _jcs(obj) == expected


def test_tuple_list_farki_yok():
    """ORTAM-OGRENDI: (1,2) ve [1,2] byte-ayni serilesir — RFC 8785'de
    'dizi' tek-tur vardir, Python tuple'i ayirt etmez (parite icin kritik)."""
    assert _jcs((1, 2, 3)) == _jcs([1, 2, 3])


def test_icice_karma_tip():
    """ORTAM: dict icinde tuple, tuple icinde dict — derin yuvalama calisir."""
    assert _jcs({"k": (1, {"j": 2})}) == '{"k":[1,{"j":2}]}'


def test_bos_dict_ayrac_yok():
    """ORTAM: bos dict/konteyner'da gereksiz ayrac YOK."""
    assert _jcs({}) == "{}"
    assert _jcs([]) == "[]"


# == _jcs: sabit-ozellikler ======================================================================

@pytest.mark.parametrize("obj", [
    {"a": 1, "b": 2},
    [1, 2, 3],
    {"z": {"y": [1, {"x": None}]}},
    "test\"value",
    {"k": "😀"},
])
def test_json_ayristirilebilir(obj):
    """ORTAM: cikti gecerli JSON'dur (json.loads round-trip)."""
    import json
    parsed = json.loads(_jcs(obj))
    assert parsed == json.loads(json.dumps(obj, sort_keys=True))


@pytest.mark.parametrize("obj", [
    {"a": 1, "b": 2, "c": 3, "d": 4, "e": 5},
    {"e": 5, "d": 4, "c": 3, "b": 2, "a": 1},
    {"c": 3, "a": 1, "e": 5, "b": 2, "d": 4},
])
def test_girdi_sirasi_bagimsiz(obj):
    """ORTAM: ayni icerik farkli dict-sirasinda ayni cikti (kanonik)."""
    expected = '{"a":1,"b":2,"c":3,"d":4,"e":5}'
    assert _jcs(obj) == expected


@pytest.mark.parametrize("obj", [
    {"a": 1},
    [1, 2],
    "x",
    None,
])
def test_tipografi_bosluksuz(obj):
    """ORTAM: ciktida BOSLUK YOK — her ayraç sonra bosluk birakilmaz."""
    out = _jcs(obj)
    assert " " not in out
    assert ", " not in out
    assert ": " not in out


def test_jcs_public_alias_ayni():
    """ORTAM: `jcs` public-wrapper'i _jcs ile ayni ciktiyi verir."""
    from veridict.tamga_anchor import jcs
    for obj in [{"b": 1, "a": 2}, [1, 2], "x", None, True]:
        assert jcs(obj) == _jcs(obj)


@pytest.mark.parametrize("obj", [
    {"a": 1, "b": [1, 2, 3]},
    {"b": [1, 2, 3], "a": 1},
])
def test_deterministik(obj):
    """ORTAM: ayni degerler her cagrida ayni cikti (hash-paritesi onkosul)."""
    first = _jcs(obj)
    assert _jcs(obj) == first
    assert _jcs(obj) == first
