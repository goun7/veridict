import time

from scripts.dogfood import dogfood


def test_dogfood_audits_itself_and_verifies():
    started = time.time()
    result = dogfood()
    elapsed = time.time() - started
    assert result["cert"]["policy_mode"] == "HYBRID"
    assert result["outcome"].blocked is False
    assert result["verification"]["valid"] is True, result["verification"]["errors"]
    assert elapsed < 600   # §6.5: GATE p95 target is 30 min; smoke assert 10 min
