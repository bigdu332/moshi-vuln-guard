from vulnguard.feeds import dedupe_advisories
from vulnguard.models import Advisory, PackageRange


def test_duplicate_cve_keeps_the_record_with_cvss():
    weak = Advisory(
        id="GO-2022-0603",
        summary="Panic in gopkg.in/yaml.v3",
        aliases=["CVE-2022-28948"],
        cvss=None,
        packages=[PackageRange("Go", "gopkg.in/yaml.v3", [{"introduced": "0", "fixed": "3.0.1"}], ["3.0.1"])],
    )
    strong = Advisory(
        id="GHSA-hp87-p4gw-j4gq",
        summary="gopkg.in/yaml.v3 Denial of Service",
        aliases=["CVE-2022-28948", "GO-2022-0603"],
        cvss=7.5,
        packages=[PackageRange("Go", "gopkg.in/yaml.v3", [{"introduced": "0", "fixed": "3.0.1"}], ["3.0.1"])],
    )
    merged = dedupe_advisories([weak, strong])
    assert len(merged) == 1
    assert merged[0].cvss == 7.5
    assert merged[0].canonical_id() == "CVE-2022-28948"
    assert "GO-2022-0603" in merged[0].aliases_all()
