"""把 Trivy 的 JSON 当作第二意见附到报告上，不替换 OSV 主路径。"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

from vulnguard.models import Finding

Runner = Callable[[list[str]], tuple[int, str, str]]


def trivy_on_path() -> bool:
    return shutil.which("trivy") is not None


def parse_trivy_json(payload: dict[str, Any], *, origin: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for result in payload.get("Results") or []:
        target = str(result.get("Target") or "")
        for vuln in result.get("Vulnerabilities") or []:
            vuln_id = str(vuln.get("VulnerabilityID") or "").strip()
            pkg = str(vuln.get("PkgName") or "").strip()
            if not vuln_id or not pkg:
                continue
            cvss = _cvss_score(vuln.get("CVSS") or {})
            hits.append(
                {
                    "vuln_id": vuln_id,
                    "pkg_name": pkg,
                    "installed": str(vuln.get("InstalledVersion") or ""),
                    "fixed": str(vuln.get("FixedVersion") or ""),
                    "severity": str(vuln.get("Severity") or ""),
                    "title": str(vuln.get("Title") or vuln.get("Description") or "")[:240],
                    "url": str(vuln.get("PrimaryURL") or ""),
                    "target": target,
                    "cvss": cvss,
                    "origin": origin,
                    "in_osv": False,
                    "same_package": False,
                }
            )
    return _dedupe(hits)


def annotate_overlap(hits: list[dict[str, Any]], findings: list[Finding]) -> None:
    names_by_cve: dict[str, set[str]] = {}
    for finding in findings:
        bucket = names_by_cve.setdefault(finding.vuln_id, set())
        bucket.add(finding.asset.name.lower())
        if finding.asset.product:
            bucket.add(finding.asset.product.lower())
    for hit in hits:
        names = names_by_cve.get(hit["vuln_id"], set())
        hit["in_osv"] = hit["vuln_id"] in names_by_cve
        hit["same_package"] = hit["pkg_name"].lower() in names


def relation_label(hit: dict[str, Any]) -> str:
    if hit.get("same_package"):
        return "与 OSV 主路径重合"
    if hit.get("in_osv"):
        return "编号已在主路径出现"
    return "仅第二意见"


def collect_trivy(
    target: Path | None,
    findings: list[Finding],
    *,
    runner: Runner | None = None,
) -> tuple[list[dict[str, Any]], list[str], str]:
    """返回命中、提示、状态（off / fixture / live / mixed）。"""
    warnings: list[str] = []
    hits: list[dict[str, Any]] = []
    used_fixture = False
    used_live = False
    if target is not None and target.is_dir():
        fixture = target / "trivy.json"
        if fixture.is_file():
            payload = json.loads(fixture.read_text(encoding="utf-8"))
            hits.extend(parse_trivy_json(payload, origin="fixture"))
            used_fixture = True
    if trivy_on_path() and target is not None and target.exists():
        run = runner or _subprocess_runner
        code, out, err = run(
            ["trivy", "fs", "--scanners", "vuln", "--format", "json", "--quiet", str(target)]
        )
        if code == 0 and out.strip():
            try:
                hits.extend(parse_trivy_json(json.loads(out), origin="trivy"))
                used_live = True
            except json.JSONDecodeError:
                warnings.append("trivy 已运行，但 stdout 不是 JSON，第二意见只保留夹具。")
        else:
            detail = (err or out).strip().splitlines()
            tail = detail[-1] if detail else "无输出"
            warnings.append(f"检测到 trivy，但这次没有可用的 JSON（{tail}）。")
    hits = _dedupe(hits)
    annotate_overlap(hits, findings)
    if used_live and used_fixture:
        status = "mixed"
        warnings.append("Trivy 第二意见来自本机 trivy 与目标目录的 trivy.json，OSV 主路径保持不变。")
    elif used_live:
        status = "live"
        warnings.append("已运行 trivy，结果作为第二意见附在报告中，不替换 OSV 发现。")
    elif used_fixture:
        status = "fixture"
        warnings.append("PATH 中没有 trivy。已读入目标目录的 trivy.json 作为第二意见，OSV 主路径保持不变。")
    else:
        status = "off"
        if target is not None and target.exists():
            warnings.append(
                "PATH 中没有 trivy，目标目录也没有 trivy.json。第二意见未附上。示例见 demo/trivy/sample.json。"
            )
    return hits, warnings, status


def _cvss_score(cvss: dict[str, Any]) -> float | None:
    for source in ("nvd", "redhat", "ghsa"):
        block = cvss.get(source) or {}
        for key in ("V3Score", "V2Score"):
            value = block.get(key)
            if isinstance(value, (int, float)):
                return float(value)
    return None


def _dedupe(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chosen: dict[tuple[str, str, str], dict[str, Any]] = {}
    order: list[tuple[str, str, str]] = []
    for hit in hits:
        key = (hit["vuln_id"], hit["pkg_name"].lower(), hit["installed"])
        if key not in chosen:
            chosen[key] = hit
            order.append(key)
            continue
        current = chosen[key]
        if current["origin"] != "trivy" and hit["origin"] == "trivy":
            hit["origin"] = "trivy"
            chosen[key] = hit
    return [chosen[key] for key in order]


def _subprocess_runner(argv: list[str]) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)
    return completed.returncode, completed.stdout, completed.stderr
