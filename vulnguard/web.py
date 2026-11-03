"""给人看的巡检界面。页面由服务端渲染，批准和预演走表单。"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from vulnguard.paths import repo_root
from vulnguard.pipeline import scan_and_write
from vulnguard.priority import band_label, exposure_label
from vulnguard.remediate import execute, preview
from vulnguard.store import Approval, Store, plan_from_dict

PACKAGE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(PACKAGE / "templates"))
templates.env.filters["band_label"] = band_label
templates.env.filters["exposure_label"] = exposure_label
templates.env.filters["cvss"] = lambda value: "—" if value is None else f"{float(value):.1f}"
templates.env.filters["epss"] = lambda value: "—" if value is None else f"{float(value):.4f}"


def create_app(store: Store, settings: dict) -> FastAPI:
    app = FastAPI(title="VulnGuard")
    app.mount("/static", StaticFiles(directory=str(PACKAGE / "static")), name="static")

    def latest() -> dict | None:
        return store.latest()

    @app.get("/")
    def dashboard(request: Request, band: str = "", kev: str = ""):
        scan = _with_plan_status(store, latest())
        findings = []
        if scan:
            findings = scan["findings"]
            if band:
                findings = [item for item in findings if item["band"] == band]
            if kev == "1":
                findings = [item for item in findings if item["kev"]]
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "scan": scan,
                "findings": findings,
                "band": band,
                "kev": kev,
                "counts": _counts(scan),
                "settings": settings,
            },
        )

    @app.get("/assets")
    def assets(request: Request):
        scan = latest()
        return templates.TemplateResponse(request, "assets.html", {"scan": scan, "assets": (scan or {}).get("assets") or []})

    @app.get("/findings/{finding_id}")
    def finding_detail(request: Request, finding_id: str):
        scan = latest()
        if not scan:
            raise HTTPException(404)
        finding = next((item for item in scan["findings"] if item["id"] == finding_id), None)
        if not finding:
            raise HTTPException(404)
        plan = next((item for item in scan["plans"] if finding_id in item.get("finding_ids", [])), None)
        if plan:
            plan = store.get_plan(plan["id"]) or plan
        return templates.TemplateResponse(
            request,
            "finding.html",
            {"scan": scan, "finding": finding, "plan": plan},
        )

    @app.get("/plans/{plan_id}")
    def plan_detail(request: Request, plan_id: str, error: str = ""):
        plan = store.get_plan(plan_id)
        if not plan:
            raise HTTPException(404)
        scan = store.get_scan(plan.get("scan_id") or "") or latest()
        findings = []
        if scan:
            wanted = set(plan.get("finding_ids") or [])
            findings = [item for item in scan["findings"] if item["id"] in wanted]
        return templates.TemplateResponse(
            request,
            "plan.html",
            {
                "plan": plan,
                "findings": findings,
                "approvals": store.approvals_for(plan_id),
                "allow_apply": _allow_apply(),
                "error": error,
            },
        )

    @app.post("/scans")
    def start_scan(source: str = Form("fixture"), path: str = Form("demo/lab"), online: str = Form("")):
        out = repo_root() / "runtime" / "reports" / "latest"
        scan_and_write(source, path, out, online=online == "1", ssh_user=None, store=store)
        return RedirectResponse("/", status_code=303)

    @app.post("/plans/{plan_id}/decision")
    def decide(
        plan_id: str,
        decision: str = Form(...),
        approver: str = Form(...),
        comment: str = Form(...),
        confirm: str = Form(""),
    ):
        plan = store.get_plan(plan_id)
        if not plan:
            raise HTTPException(404)
        approver = approver.strip()
        comment = comment.strip()
        if len(approver) < 2 or len(comment) < 4:
            return RedirectResponse(f"/plans/{plan_id}?error=need-comment", status_code=303)
        if decision == "approved" and confirm != "yes":
            return RedirectResponse(f"/plans/{plan_id}?error=need-confirm", status_code=303)
        if decision not in {"approved", "rejected", "accepted"}:
            raise HTTPException(400)
        plan["status"] = decision
        store.update_plan(plan)
        store.add_approval(
            Approval(
                plan_id=plan_id,
                scan_id=plan.get("scan_id") or "",
                decision=decision,
                approver=approver,
                comment=comment,
                created_at=_now(),
            )
        )
        return RedirectResponse(f"/plans/{plan_id}", status_code=303)

    @app.post("/plans/{plan_id}/dry-run")
    def dry_run(plan_id: str):
        plan = store.get_plan(plan_id)
        if not plan:
            raise HTTPException(404)
        text = preview(plan_from_dict(plan))
        plan["last_preview"] = text
        plan["last_preview_at"] = _now()
        store.update_plan(plan)
        return RedirectResponse(f"/plans/{plan_id}", status_code=303)

    @app.post("/plans/{plan_id}/apply")
    def apply(plan_id: str):
        plan_payload = store.get_plan(plan_id)
        if not plan_payload:
            raise HTTPException(404)
        model = plan_from_dict(plan_payload)
        try:
            text = execute(
                model,
                approved=plan_payload.get("status") == "approved",
                allow_apply=_allow_apply(),
                runner=_runner,
            )
        except PermissionError as exc:
            plan_payload["last_preview"] = f"[拒绝] {exc}"
            store.update_plan(plan_payload)
            return RedirectResponse(f"/plans/{plan_id}?error=denied", status_code=303)
        plan_payload["last_preview"] = text
        plan_payload["last_preview_at"] = _now()
        store.update_plan(plan_payload)
        return RedirectResponse(f"/plans/{plan_id}", status_code=303)

    @app.get("/report.md")
    def report_markdown():
        path = _report_file("report.md")
        if not path:
            raise HTTPException(404)
        return FileResponse(path, media_type="text/markdown; charset=utf-8", filename="report.md")

    @app.get("/report.html")
    def report_html():
        path = _report_file("report.html")
        if not path:
            raise HTTPException(404)
        return FileResponse(path, media_type="text/html; charset=utf-8")

    @app.get("/api/scan")
    def api_scan():
        scan = latest()
        if not scan:
            return {"scan": None}
        return {
            "id": scan["id"],
            "host": scan["host"],
            "asset_count": len(scan["assets"]),
            "finding_count": len(scan["findings"]),
            "feeds": scan.get("feeds") or {},
            "findings": [
                {"id": item["vuln_id"], "asset": item["asset"]["name"], "band": item["band"], "score": item["score"], "kev": item["kev"]}
                for item in scan["findings"]
            ],
        }

    return app


def serve(host: str, port: int, db: Path, source: str, path: str, interval_hours: float, scan_on_start: bool, online: bool) -> None:
    store = Store(db)
    settings = {"source": source, "path": path, "online": online}
    if scan_on_start or store.latest() is None:
        out = repo_root() / "runtime" / "reports" / "latest"
        scan_and_write(source, path, out, online=online, store=store)
    if interval_hours > 0:
        thread = threading.Thread(
            target=_loop,
            args=(store, source, path, online, interval_hours),
            daemon=True,
            name="vulnguard-scheduler",
        )
        thread.start()
    import uvicorn

    uvicorn.run(create_app(store, settings), host=host, port=port, log_level="info")


def _loop(store: Store, source: str, path: str, online: bool, interval_hours: float) -> None:
    while True:
        time.sleep(max(interval_hours, 0.01) * 3600)
        out = repo_root() / "runtime" / "reports" / "scheduled"
        scan_and_write(source, path, out, online=online, store=store)


def _with_plan_status(store: Store, scan: dict | None) -> dict | None:
    if not scan:
        return None
    for plan in scan.get("plans") or []:
        current = store.get_plan(plan["id"])
        if current:
            plan["status"] = current.get("status") or plan.get("status")
            plan["last_preview"] = current.get("last_preview")
    return scan


def _report_file(name: str) -> Path | None:
    for relative in ("runtime/reports/latest", "artifacts/demo-run"):
        path = repo_root() / relative / name
        if path.exists():
            return path
    return None


def _counts(scan: dict | None) -> dict[str, int]:
    counts = {"assets": 0, "findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "kev": 0, "plans": 0}
    if not scan:
        return counts
    counts["assets"] = len(scan.get("assets") or [])
    counts["plans"] = len(scan.get("plans") or [])
    for item in scan.get("findings") or []:
        counts["findings"] += 1
        counts[item["band"]] = counts.get(item["band"], 0) + 1
        if item.get("kev"):
            counts["kev"] += 1
    return counts


def _allow_apply() -> bool:
    return os_environ_flag("VULNGUARD_ALLOW_APPLY")


def os_environ_flag(name: str) -> bool:
    import os

    return os.environ.get(name, "").strip() in {"1", "true", "TRUE", "yes"}


def _runner(argv: list[str]) -> tuple[int, str, str]:
    import subprocess

    completed = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
    return completed.returncode, completed.stdout, completed.stderr


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
