import pickle

from calc import load_profile


def test_roundtrip():
    obj = {"a": 1}
    assert load_profile(pickle.dumps(obj)) == obj
