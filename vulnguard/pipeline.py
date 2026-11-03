"""把采集、匹配、排序、建议和报告串起来。"""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from vulnguard.advise import render_narratives
from vulnguard.feeds import FeedSet, load_feeds
from vulnguard.inventory import collect_docker, collect_fixture, collect_local, collect_ssh
from vulnguard.match import match_assets
from vulnguard.models import ScanResult
from vulnguard.paths import repo_root
from vulnguard.remediate import build_plans
from vulnguard.report import write_reports


def run_scan(
    source: str,
    target: str,
    *,
    online: bool = True,
    ssh_user: str | None = None,
    ssh_port: int = 22,
    feeds: FeedSet | None = None,
) -> ScanResult:
    warnings: list[str] = []
    chosen = source
    path = Path(target)
    if source == "auto":
        try:
            assets, warnings, host = collect_docker()
            chosen = "docker"
            if not assets:
                raise RuntimeError("Docker 没有采集到资产")
        except Exception as exc:
            warnings.append(f"Docker 采集不可用：{exc}")
            assets, extra, host = collect_fixture(path if path.exists() else repo_root() / "demo" / "lab")
            warnings.extend(extra)
            chosen = "fixture"
    elif source == "fixture":
        assets, warnings, host = collect_fixture(path)
    elif source == "local":
        assets, warnings, host = collect_local(path)
    elif source == "docker":
        assets, warnings, host = collect_docker()
    elif source == "ssh":
        assets, warnings, host = collect_ssh(target, user=ssh_user, port=ssh_port)
    else:
        raise ValueError(f"不支持的来源：{source}")
    missing = [name for name in ("trivy", "grype", "syft", "osv-scanner") if shutil.which(name) is None]
    if missing:
        warnings.append(
            "未检测到 "
            + "、".join(missing)
            + "。本次使用内置匹配。这些项目的仓库链接写在 docs/设计文档.md。"
        )
    feedset = feeds if feeds is not None else load_feeds(online=online)
    findings = match_assets(assets, feedset)
    plans = build_plans(findings)
    render_narratives(plans, findings)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return ScanResult(
        id=f"scan-{stamp}",
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        source=chosen,
        target=str(target),
        host=host,
        assets=assets,
        findings=findings,
        plans=plans,
        warnings=warnings,
        feeds=dict(feedset.status),
    )


def scan_and_write(
    source: str,
    target: str,
    out: Path,
    *,
    online: bool = True,
    ssh_user: str | None = None,
    store=None,
) -> ScanResult:
    scan = run_scan(source, target, online=online, ssh_user=ssh_user)
    write_reports(scan, out)
    if store is not None:
        store.save_scan(scan)
    return scan
