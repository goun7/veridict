from calc import top_scores


def test_top_scores_count():
    assert len(top_scores([7, 3, 9, 1])) == 3   # only checks the count
