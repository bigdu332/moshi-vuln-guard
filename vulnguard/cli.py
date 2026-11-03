"""命令行入口。"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from vulnguard.feeds import refresh_snapshots
from vulnguard.paths import repo_root
from vulnguard.pipeline import scan_and_write
from vulnguard.remediate import preview
from vulnguard.store import Store, plan_from_dict


def main() -> None:
    parser = argparse.ArgumentParser(prog="vulnguard", description="对照公开漏洞清单，生成可复核的更新建议")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="巡检并写出报告")
    _add_scan_args(scan)

    demo = sub.add_parser("demo", help="用演示环境跑一遍并写出样例报告")
    demo.add_argument("--online", action="store_true", help="访问 OSV、KEV 和 EPSS")
    demo.add_argument("--out", default="artifacts/demo-run")
    demo.add_argument("--db", default="runtime/vulnguard.db")

    serve = sub.add_parser("serve", help="启动 Web 界面")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--db", default="runtime/vulnguard.db")
    serve.add_argument("--source", default="auto")
    serve.add_argument("--path", default="demo/lab")
    serve.add_argument("--interval-hours", type=float, default=0)
    serve.add_argument("--scan-on-start", action="store_true")
    serve.add_argument("--online", action="store_true")

    sub.add_parser("refresh-feeds", help="刷新随包的 OSV / KEV / EPSS 快照")

    dry = sub.add_parser("dry-run", help="对已保存的方案做预演")
    dry.add_argument("plan_id")
    dry.add_argument("--db", default="runtime/vulnguard.db")

    approve = sub.add_parser("approve", help="批准一个方案")
    approve.add_argument("plan_id")
    approve.add_argument("--approver", required=True)
    approve.add_argument("--comment", required=True)
    approve.add_argument("--db", default="runtime/vulnguard.db")

    args = parser.parse_args()
    root = repo_root()
    os.chdir(root)
    if args.command == "scan":
        scan_and_write(
            args.source,
            args.path,
            Path(args.out),
            online=args.online,
            ssh_user=args.ssh_user,
            store=Store(Path(args.db)),
        )
        print(f"报告已写入 {args.out}")
    elif args.command == "demo":
        result = scan_and_write(
            "fixture",
            "demo/lab",
            Path(args.out),
            online=args.online,
            store=Store(Path(args.db)),
        )
        print(f"主机 {result.host}，资产 {len(result.assets)}，发现 {len(result.findings)}，方案 {len(result.plans)}")
        print(f"报告：{args.out}/report.md")
        print("下一步：python -m vulnguard serve")
    elif args.command == "serve":
        from vulnguard.web import serve

        serve(
            host=args.host,
            port=args.port,
            db=Path(args.db),
            source=args.source,
            path=args.path,
            interval_hours=args.interval_hours,
            scan_on_start=args.scan_on_start,
            online=args.online,
        )
    elif args.command == "refresh-feeds":
        print(refresh_snapshots())
    elif args.command == "dry-run":
        store = Store(Path(args.db))
        payload = store.get_plan(args.plan_id)
        if not payload:
            raise SystemExit(f"找不到方案 {args.plan_id}")
        print(preview(plan_from_dict(payload)))
    elif args.command == "approve":
        from datetime import datetime, timezone

        store = Store(Path(args.db))
        payload = store.get_plan(args.plan_id)
        if not payload:
            raise SystemExit(f"找不到方案 {args.plan_id}")
        payload["status"] = "approved"
        store.update_plan(payload)
        store.add_approval(
            __import__("vulnguard.store", fromlist=["Approval"]).Approval(
                plan_id=args.plan_id,
                scan_id=payload.get("scan_id") or "",
                decision="approved",
                approver=args.approver,
                comment=args.comment,
                created_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            )
        )
        print(f"已批准 {args.plan_id}")


def _add_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source", choices=["auto", "fixture", "local", "docker", "ssh"], default="fixture")
    parser.add_argument("--path", default="demo/lab", help="fixture/local 目录，或 SSH 主机")
    parser.add_argument("--ssh-user", default=None)
    parser.add_argument("--out", default="artifacts/demo-run")
    parser.add_argument("--db", default="runtime/vulnguard.db")
    parser.add_argument("--online", action="store_true")
