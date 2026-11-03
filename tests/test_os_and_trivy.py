import json
from pathlib import Path

from vulnguard.inventory import collect_docker, collect_fixture, collect_local, parse_apk, parse_remote_inventory, parse_rpm
from vulnguard.paths import repo_root
from vulnguard.pipeline import run_scan
from vulnguard.trivy import annotate_overlap, parse_trivy_json, relation_label


def test_rpm_and_apk_parsers():
    rpm = parse_rpm("nginx\t1.18.0-1.el7\n(none) ignored\nbash\t(none):4.2.46-34.el7\n", "t", "rpm")
    by_name = {item.name: item for item in rpm if item.version}
    assert by_name["nginx"].ecosystem == "rpm"
    assert by_name["nginx"].version == "1.18.0-1.el7"
    assert by_name["nginx"].kind == "middleware"
    assert by_name["bash"].version == "4.2.46-34.el7"
    apk = parse_apk("nginx-1.18.0-r1\nbusybox-1.36.1-r15\n# comment\n", "t", "apk")
    assert {item.name for item in apk} == {"nginx", "busybox"}
    nginx = next(item for item in apk if item.name == "nginx")
    assert nginx.ecosystem == "Alpine"
    assert nginx.version == "1.18.0-r1"


def test_fixture_reads_rpm_and_apk_files():
    assets, warnings, host = collect_fixture(repo_root() / "demo" / "samples" / "rpm-apk")
    assert host == "rpm-apk-lab"
    assert warnings == []
    ecosystems = {(asset.name, asset.ecosystem) for asset in assets}
    assert ("nginx", "rpm") in ecosystems
    assert ("nginx", "Alpine") in ecosystems
    assert ("busybox", "Alpine") in ecosystems


def test_remote_sections_include_rpm_and_apk():
    text = """===RPM===
redis\t5.0.7-1.el7
===APK===
nginx-1.18.0-r1
===END===
"""
    assets = parse_remote_inventory(text, "ssh:demo")
    assert {asset.ecosystem for asset in assets} == {"rpm", "Alpine"}


def test_docker_filter_and_retry(monkeypatch):
    monkeypatch.setenv("VULNGUARD_DOCKER_PS_FILTER", "label=vulnguard.scan=true")
    calls = {"ps": 0}

    def runner(argv):
        if argv[:2] == ["docker", "ps"]:
            calls["ps"] += 1
            assert argv[2:4] == ["--filter", "label=vulnguard.scan=true"]
            if calls["ps"] == 1:
                return 1, "", "Cannot connect to the Docker daemon"
            return 0, "abc\tedge-nginx\tnginx:1.18.0\n", ""
        if argv[:4] == ["docker", "exec", "abc", "nginx"]:
            return 0, "nginx version: nginx/1.18.0\n", ""
        return 1, "", "missing"

    assets, warnings, _host = collect_docker(runner, attempts=3, pause=0)
    assert calls["ps"] == 2
    assert any(asset.name == "nginx" and asset.source == "docker:edge-nginx" for asset in assets)
    assert any("第 2 次" in item for item in warnings)


def test_scan_prints_source(capsys):
    from vulnguard.pipeline import run_scan

    run_scan("fixture", "demo/samples/rpm-apk", online=False)
    assert "巡检来源=fixture" in capsys.readouterr().out


def test_local_skips_missing_package_managers():
    def runner(argv):
        if argv[0] == "dpkg-query":
            return 0, "bash\t5.2-1\n", ""
        return 127, "", "not found"

    assets, warnings, host = collect_local(repo_root() / "demo" / "lab" / "app", runner)
    assert host == "localhost"
    assert any(asset.name == "bash" and asset.ecosystem == "Debian" for asset in assets)
    assert any("rpm" in item for item in warnings)
    assert any("apk" in item for item in warnings)


def test_trivy_json_marks_overlap_without_replacing_osv():
    payload = json.loads((repo_root() / "demo" / "trivy" / "sample.json").read_text(encoding="utf-8"))
    hits = parse_trivy_json(payload, origin="fixture")
    assert {item["vuln_id"] for item in hits} == {"CVE-2020-14343", "TRIVY-SAMPLE-ONLY"}
    scan = run_scan("fixture", "demo/lab", online=False)
    annotate_overlap(hits, scan.findings)
    by_id = {item["vuln_id"]: item for item in hits}
    assert by_id["CVE-2020-14343"]["same_package"] is True
    assert relation_label(by_id["CVE-2020-14343"]) == "与 OSV 主路径重合"
    assert relation_label(by_id["TRIVY-SAMPLE-ONLY"]) == "仅第二意见"
    assert any(item.vuln_id == "CVE-2020-14343" for item in scan.findings)
    assert all(item.vuln_id != "TRIVY-SAMPLE-ONLY" for item in scan.findings)
    assert any(item["vuln_id"] == "TRIVY-SAMPLE-ONLY" for item in scan.trivy)
    assert scan.feeds["trivy"] in {"fixture", "live", "mixed"}


def test_report_keeps_trivy_as_secondary(tmp_path: Path):
    scan = run_scan("fixture", "demo/lab", online=False)
    from vulnguard.report import render_markdown

    text = render_markdown(scan)
    assert "## Trivy 第二意见" in text
    assert "TRIVY-SAMPLE-ONLY" in text
    assert "与 OSV 主路径重合" in text
    assert "VULNGUARD_ALLOW_APPLY" in text
