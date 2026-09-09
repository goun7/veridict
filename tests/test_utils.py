from veridict.utils import canonical_json, sha256_hex, payload_digest, iter_python_files

def test_canonical_json_sorts_and_compacts():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'

def test_sha256_hex_known_vector():
    assert sha256_hex("abc") == ("ba7816bf8f01cfea414140de5dae2223"
                                  "b00361a396177a9cb410ff61f20015ad")

def test_payload_digest_is_stable_across_key_order():
    assert payload_digest({"x": 1, "y": 2}) == payload_digest({"y": 2, "x": 1})

def test_iter_python_files_skips_ignored_dirs(tmp_path):
    (tmp_path / "veridict").mkdir(); (tmp_path / "veridict" / "a.py").write_text("x = 1")
    (tmp_path / "__pycache__").mkdir(); (tmp_path / "__pycache__" / "junk.py").write_text("")
    rels = iter_python_files(str(tmp_path))
    assert rels == ["veridict/a.py"]
