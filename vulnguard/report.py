"""写出 Markdown 和可单独打开的 HTML 报告。"""

from __future__ import annotations

from html import escape
from pathlib import Path

from vulnguard.models import ScanResult
from vulnguard.priority import band_label, exposure_label
from vulnguard.trivy import relation_label

BAND_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def write_reports(scan: ScanResult, directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    markdown = directory / "report.md"
    html = directory / "report.html"
    data = directory / "findings.json"
    markdown.write_text(render_markdown(scan), encoding="utf-8")
    html.write_text(render_html(scan), encoding="utf-8")
    data.write_text(
        __import__("json").dumps(scan.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return markdown, html


def render_markdown(scan: ScanResult) -> str:
    counts = _counts(scan)
    lines = [
        f"# VulnGuard 巡检报告 {scan.id}",
        "",
        f"- 时间：{scan.created_at}",
        f"- 目标：{scan.host}（来源 {scan.source}，路径 {scan.target}）",
        f"- 资产 {len(scan.assets)}，发现 {len(scan.findings)}，"
        f"严重 {counts['critical']}，高危 {counts['high']}，中危 {counts['medium']}，低危 {counts['low']}",
        f"- 数据源：OSV {scan.feeds.get('osv', 'off')}，KEV {scan.feeds.get('kev', 'off')}，"
        f"EPSS {scan.feeds.get('epss', 'off')}，Trivy {scan.feeds.get('trivy', 'off')}",
        "",
        "## 优先处理",
        "",
        "| 等级 | 资产 | 版本 | 编号 | CVSS | KEV | EPSS | 综合分 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for finding in scan.findings[:20]:
        cvss = "" if finding.advisory.cvss is None else f"{finding.advisory.cvss:.1f}"
        epss = "" if finding.epss is None else f"{finding.epss:.4f}"
        lines.append(
            f"| {band_label(finding.band)} | {finding.asset.name} | {finding.asset.version} | "
            f"{finding.vuln_id} | {cvss} | {'是' if finding.kev else ''} | {epss} | {finding.score:.4f} |"
        )
    lines.extend(["", "## Trivy 第二意见", ""])
    lines.extend(_trivy_markdown(scan))
    lines.extend(["", "## 更新方案", ""])
    for plan in scan.plans:
        lines.append(f"### {plan.title}")
        lines.append("")
        lines.append(f"- 等级：{band_label(plan.band)}")
        lines.append(f"- 目标：{plan.target_version or '人工确定'}")
        lines.append(f"- 时限：{plan.window}")
        lines.append(f"- 执行方式：{'批准后可执行白名单命令' if plan.mode == 'auto_eligible' else '仅人工执行'}")
        lines.append("")
        lines.append(plan.narrative)
        lines.append("")
    if scan.warnings:
        lines.extend(["## 采集提示", ""])
        lines.extend(f"- {item}" for item in scan.warnings)
    lines.extend(
        [
            "",
            "## 说明",
            "",
            "综合分 = min(1, CVSS/10 + KEV×0.25 + EPSS×0.15) × 暴露面系数。",
            "暴露面系数：互联网 1.00，内网 0.85，仅本机 0.70。",
            "KEV 且 CVSS 不低于 7 时，等级至少为严重。",
            "默认只生成建议和预演记录。执行白名单命令还需要人工批准，以及环境变量 VULNGUARD_ALLOW_APPLY=1。",
            "Trivy 一节是第二意见，不参与方案里的命令，也不替换上面的 OSV 发现。",
            "",
        ]
    )
    return "\n".join(lines)


def render_html(scan: ScanResult) -> str:
    counts = _counts(scan)
    rows = []
    for finding in scan.findings:
        cvss = "" if finding.advisory.cvss is None else f"{finding.advisory.cvss:.1f}"
        epss = "—" if finding.epss is None else f"{finding.epss:.4f}"
        rows.append(
            "<tr>"
            f"<td class='band {escape(finding.band)}'>{escape(band_label(finding.band))}</td>"
            f"<td>{escape(finding.asset.name)}<br><span>{escape(finding.asset.version)}</span></td>"
            f"<td>{escape(finding.vuln_id)}<br><span>{escape(finding.advisory.summary)}</span></td>"
            f"<td>{escape(cvss)}</td>"
            f"<td>{'KEV' if finding.kev else ''}</td>"
            f"<td>{escape(epss)}</td>"
            f"<td>{escape(exposure_label(finding.asset.exposure))}</td>"
            f"<td>{finding.score:.4f}</td>"
            "</tr>"
        )
    plans = []
    for plan in scan.plans:
        steps = "".join(f"<li>{escape(step.display)}</li>" for step in plan.steps)
        plans.append(
            f"<article><h3>{escape(plan.title)}</h3>"
            f"<p>{escape(plan.window)}。目标 {escape(plan.target_version or '人工确定')}。</p>"
            f"<pre>{escape(plan.narrative)}</pre><ol>{steps}</ol></article>"
        )
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>VulnGuard 报告 {escape(scan.id)}</title>
<style>
body {{ margin: 0; background: #f3f0e8; color: #1a2332; font: 15px/1.6 "WenQuanYi Micro Hei", "Droid Sans Fallback", sans-serif; }}
main {{ width: min(1080px, calc(100% - 32px)); margin: 24px auto 48px; }}
h1 {{ font-size: 28px; margin-bottom: 4px; }}
.meta {{ color: #526072; }}
.cards {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 18px 0; }}
.card {{ background: white; border-radius: 12px; padding: 12px 14px; }}
.card b {{ display: block; font-size: 24px; }}
table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 12px; overflow: hidden; }}
th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #ece7dc; vertical-align: top; }}
td span {{ color: #526072; font-size: 12px; }}
.band {{ font-weight: 700; }}
.critical {{ color: #9b1c31; }} .high {{ color: #c2410c; }} .medium {{ color: #a16207; }} .low {{ color: #3f6212; }}
article {{ background: white; border-radius: 12px; padding: 8px 16px 16px; margin-top: 12px; }}
pre {{ white-space: pre-wrap; font: inherit; }}
</style>
</head>
<body>
<main>
<h1>VulnGuard 巡检报告</h1>
<p class="meta">{escape(scan.host)} · {escape(scan.created_at)} · {escape(scan.source)}</p>
<section class="cards">
<div class="card"><b>{len(scan.assets)}</b>资产</div>
<div class="card"><b>{counts['critical']}</b>严重</div>
<div class="card"><b>{counts['high']}</b>高危</div>
<div class="card"><b>{counts['medium']}</b>中危</div>
<div class="card"><b>{sum(1 for item in scan.findings if item.kev)}</b>KEV</div>
</section>
<table>
<thead><tr><th>等级</th><th>资产</th><th>条目</th><th>CVSS</th><th>KEV</th><th>EPSS</th><th>暴露面</th><th>综合分</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
<h2>Trivy 第二意见</h2>
{''.join(_trivy_html(scan))}
<h2>更新方案</h2>
{''.join(plans)}
</main>
</body>
</html>
"""


def _trivy_markdown(scan: ScanResult) -> list[str]:
    if not scan.trivy:
        return ["这次没有附上 Trivy 结果。OSV 主路径不受影响。", ""]
    lines = [
        "下表来自 Trivy JSON 或本机 `trivy fs`。它不进入更新方案，也不改写上面的发现。",
        "",
        "| 编号 | 包 | 已安装 | 修复版本 | 严重性 | 对照 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for hit in scan.trivy:
        lines.append(
            f"| {hit['vuln_id']} | {hit['pkg_name']} | {hit['installed']} | {hit['fixed']} | "
            f"{hit['severity']} | {relation_label(hit)} |"
        )
    lines.append("")
    return lines


def _trivy_html(scan: ScanResult) -> list[str]:
    if not scan.trivy:
        return ["<p>这次没有附上 Trivy 结果。OSV 主路径不受影响。</p>"]
    rows = []
    for hit in scan.trivy:
        rows.append(
            "<tr>"
            f"<td>{escape(hit['vuln_id'])}</td>"
            f"<td>{escape(hit['pkg_name'])} {escape(hit['installed'])}</td>"
            f"<td>{escape(hit['fixed'])}</td>"
            f"<td>{escape(hit['severity'])}</td>"
            f"<td>{escape(relation_label(hit))}</td>"
            "</tr>"
        )
    return [
        "<p>下表是第二意见，不进入更新方案。</p>",
        "<table><thead><tr><th>编号</th><th>包</th><th>修复版本</th><th>严重性</th><th>对照</th></tr></thead>",
        "<tbody>",
        *rows,
        "</tbody></table>",
    ]


def _counts(scan: ScanResult) -> dict[str, int]:
    counts = {key: 0 for key in BAND_ORDER}
    for finding in scan.findings:
        counts[finding.band] = counts.get(finding.band, 0) + 1
    return counts
