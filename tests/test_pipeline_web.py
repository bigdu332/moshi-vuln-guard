from pathlib import Path

from fastapi.testclient import TestClient

from vulnguard.pipeline import run_scan
from vulnguard.store import Store
from vulnguard.web import create_app


def test_offline_scan_writes_chinese_report(tmp_path: Path):
    scan = run_scan("fixture", "demo/lab", online=False)
    assert scan.host == "moshi-lab-01"
    assert any(item.vuln_id == "CVE-2021-44228" for item in scan.findings)
    pyyaml = next(item for item in scan.plans if item.asset.name == "pyyaml")
    assert "PyYAML" in pyyaml.narrative or "pyyaml" in pyyaml.narrative
    assert pyyaml.narrative_source == "template"
    from vulnguard.report import write_reports

    markdown, _html = write_reports(scan, tmp_path)
    text = markdown.read_text(encoding="utf-8")
    assert "CVE-2022-0543" in text
    assert "综合分" in text


def test_web_approval_and_dry_run(tmp_path: Path):
    store = Store(tmp_path / "vuln.db")
    scan = run_scan("fixture", "demo/lab", online=False)
    store.save_scan(scan)
    app = create_app(store, {"source": "fixture", "path": "demo/lab", "online": False})
    client = TestClient(app)
    home = client.get("/")
    assert home.status_code == 200
    assert "moshi-lab-01" in home.text
    assert "CVE-2021-44228" in home.text
    plan_id = next(plan.id for plan in scan.plans if plan.asset.name == "nginx")
    denied = client.post(f"/plans/{plan_id}/apply", follow_redirects=False)
    assert denied.status_code == 303
    page = client.get(f"/plans/{plan_id}")
    assert "拒绝" in page.text
    approve = client.post(
        f"/plans/{plan_id}/decision",
        data={"decision": "approved", "approver": "值班人甲", "comment": "已核对回滚步骤", "confirm": "yes"},
        follow_redirects=False,
    )
    assert approve.status_code == 303
    dry = client.post(f"/plans/{plan_id}/dry-run", follow_redirects=True)
    assert "预演" in dry.text
    assert "apt-get" not in dry.text or "人工" in dry.text
    api = client.get("/api/scan").json()
    assert api["finding_count"] >= 7
