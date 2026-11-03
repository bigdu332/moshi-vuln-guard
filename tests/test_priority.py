from vulnguard.priority import prioritize


def test_kev_forces_critical():
    score, band, rationale = prioritize(10.0, kev=True, epss=0.97, exposure="internet")
    assert band == "critical"
    assert score >= 0.85
    assert "KEV" in rationale


def test_nginx_internet_is_high_not_inflated_to_critical():
    score, band, _ = prioritize(7.7, kev=False, epss=0.02, exposure="internet")
    assert band == "high"
    assert 0.6 <= score < 0.85


def test_missing_epss_does_not_pretend_zero_probability_in_words():
    _, _, rationale = prioritize(5.0, kev=False, epss=None, exposure="local")
    assert "未取得" in rationale


def test_local_low_cvss_stays_low():
    _, band, _ = prioritize(3.1, kev=False, epss=0.01, exposure="local")
    assert band == "low"
