"""用 SQLite 记住巡检、方案和批准记录。"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from vulnguard.models import Plan, ScanResult, Step, Asset


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  created_at TEXT,
  source TEXT,
  target TEXT,
  host TEXT,
  payload TEXT
);
CREATE TABLE IF NOT EXISTS plans (
  id TEXT PRIMARY KEY,
  scan_id TEXT,
  status TEXT,
  payload TEXT
);
CREATE TABLE IF NOT EXISTS approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plan_id TEXT,
  scan_id TEXT,
  decision TEXT,
  approver TEXT,
  comment TEXT,
  created_at TEXT
);
"""


@dataclass
class Approval:
    plan_id: str
    scan_id: str
    decision: str
    approver: str
    comment: str
    created_at: str


class Store:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.executescript(SCHEMA)

    def save_scan(self, scan: ScanResult) -> None:
        payload = json.dumps(scan.to_dict(), ensure_ascii=False)
        self.conn.execute(
            "INSERT OR REPLACE INTO scans (id, created_at, source, target, host, payload) VALUES (?, ?, ?, ?, ?, ?)",
            (scan.id, scan.created_at, scan.source, scan.target, scan.host, payload),
        )
        for plan in scan.plans:
            self.conn.execute(
                "INSERT OR REPLACE INTO plans (id, scan_id, status, payload) VALUES (?, ?, ?, ?)",
                (plan.id, scan.id, plan.status, json.dumps(plan.to_dict(), ensure_ascii=False)),
            )
        self.conn.commit()

    def latest(self) -> dict | None:
        row = self.conn.execute("SELECT payload FROM scans ORDER BY created_at DESC LIMIT 1").fetchone()
        return json.loads(row[0]) if row else None

    def get_scan(self, scan_id: str) -> dict | None:
        row = self.conn.execute("SELECT payload FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list_scans(self) -> list[dict]:
        rows = self.conn.execute("SELECT id, created_at, host, source FROM scans ORDER BY created_at DESC").fetchall()
        return [{"id": item[0], "created_at": item[1], "host": item[2], "source": item[3]} for item in rows]

    def get_plan(self, plan_id: str) -> dict | None:
        row = self.conn.execute("SELECT payload, status, scan_id FROM plans WHERE id = ?", (plan_id,)).fetchone()
        if not row:
            return None
        payload = json.loads(row[0])
        payload["status"] = row[1]
        payload["scan_id"] = row[2]
        return payload

    def update_plan(self, plan: dict) -> None:
        self.conn.execute(
            "UPDATE plans SET status = ?, payload = ? WHERE id = ?",
            (plan["status"], json.dumps(plan, ensure_ascii=False), plan["id"]),
        )
        self.conn.commit()

    def add_approval(self, approval: Approval) -> None:
        self.conn.execute(
            "INSERT INTO approvals (plan_id, scan_id, decision, approver, comment, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (approval.plan_id, approval.scan_id, approval.decision, approval.approver, approval.comment, approval.created_at),
        )
        self.conn.commit()

    def approvals_for(self, plan_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT decision, approver, comment, created_at FROM approvals WHERE plan_id = ? ORDER BY id",
            (plan_id,),
        ).fetchall()
        return [
            {"decision": item[0], "approver": item[1], "comment": item[2], "created_at": item[3]}
            for item in rows
        ]


def plan_from_dict(payload: dict) -> Plan:
    asset_data = payload["asset"]
    asset = Asset(
        name=asset_data["name"],
        version=asset_data["version"],
        ecosystem=asset_data["ecosystem"],
        kind=asset_data["kind"],
        location=asset_data["location"],
        exposure=asset_data.get("exposure") or "internal",
        host=asset_data.get("host") or "",
        source=asset_data.get("source") or "",
        evidence=asset_data.get("evidence") or "",
        product=asset_data.get("product") or "",
    )
    steps = [
        Step(title=item["title"], display=item["display"], manual=item["manual"], argv=item.get("argv"))
        for item in payload.get("steps") or []
    ]
    return Plan(
        id=payload["id"],
        asset=asset,
        title=payload["title"],
        band=payload["band"],
        target_version=payload.get("target_version"),
        mode=payload.get("mode") or "manual",
        prechecks=payload.get("prechecks") or [],
        steps=steps,
        rollback=payload.get("rollback") or [],
        verify=payload.get("verify") or [],
        window=payload.get("window") or "",
        finding_ids=payload.get("finding_ids") or [],
        command_hash=payload.get("command_hash") or "",
        narrative=payload.get("narrative") or "",
        narrative_source=payload.get("narrative_source") or "template",
        status=payload.get("status") or "pending",
    )
