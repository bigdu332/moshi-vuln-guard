from vulnguard.versioncmp import cmp_versions, version_in_range


def test_nginx_boundaries():
    assert cmp_versions("1.18.0", "1.20.1", "generic") < 0
    assert cmp_versions("1.20.1", "1.20.1", "generic") == 0
    assert cmp_versions("1.21.0", "1.20.1", "generic") > 0
    assert version_in_range("1.18.0", {"introduced": "0.6.18", "fixed": "1.20.1"}, "generic")
    assert not version_in_range("1.20.1", {"introduced": "0.6.18", "fixed": "1.20.1"}, "generic")
    assert not version_in_range("0.6.17", {"introduced": "0.6.18", "fixed": "1.20.1"}, "generic")


def test_debian_redis_epoch_and_revision():
    old = "5:5.0.7-2+deb10u1"
    fixed = "5:5.0.14-1+deb10u2"
    assert cmp_versions(old, fixed, "Debian") < 0
    assert cmp_versions("5:5.0.14-1+deb10u1", fixed, "Debian") < 0
    assert cmp_versions(fixed, fixed, "Debian") == 0
    assert cmp_versions("5:5.0.14-1+deb10u3", fixed, "Debian") > 0
    assert cmp_versions("5:6.0.16-1+deb11u1", "5:6.0.16-1+deb11u2", "Debian") < 0
    assert cmp_versions("5:7.0.15-1~deb12u7", "5:6.0.16-1+deb11u2", "Debian") > 0


def test_pypi_and_prerelease():
    assert cmp_versions("5.3.1", "5.4", "PyPI") < 0
    assert cmp_versions("5.4", "5.4.0", "PyPI") == 0
    assert cmp_versions("2.14.1", "2.15.0", "Maven") < 0
    assert cmp_versions("2.14.1", "2.0-beta9", "Maven") > 0
    assert cmp_versions("1.2.5", "1.2.6", "npm") < 0
    assert cmp_versions("v0.17.0", "v0.11.0", "Go") > 0
    assert version_in_range("1.2.5", {"introduced": "1.0.0", "fixed": "1.2.6"}, "npm")
    assert not version_in_range("1.2.5", {"introduced": "0", "fixed": "0.2.4"}, "npm")


def test_mysql_lines():
    spec_57 = {"introduced": "5.7.0", "fixed": "5.7.42"}
    spec_80 = {"introduced": "8.0.0", "fixed": "8.0.33"}
    assert version_in_range("5.7.41", spec_57, "generic")
    assert not version_in_range("5.7.42", spec_57, "generic")
    assert version_in_range("8.0.32", spec_80, "generic")
    assert not version_in_range("8.0.33", spec_80, "generic")
    assert not version_in_range("8.4.0", spec_80, "generic")
