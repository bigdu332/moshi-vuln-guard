from vulnguard.cvss import score_vector


def test_known_vectors():
    assert score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert score_vector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L") == 7.7
    assert score_vector("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H") == 7.1


def test_ignores_v4():
    assert score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
