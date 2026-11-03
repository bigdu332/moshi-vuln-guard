"""生成给人看的更新说明。有兼容 OpenAI 的接口就调用，否则使用固定模板。"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

from vulnguard.models import Finding, Plan
from vulnguard.paths import skill_path, user_prompt_path
from vulnguard.priority import band_label, exposure_label

def render_narratives(plans: list[Plan], findings: list[Finding]) -> None:
    by_id = {item.id: item for item in findings}
    grouped = []
    for plan in plans:
        rows = [by_id[item] for item in plan.finding_ids if item in by_id]
        grouped.append((plan, rows))
        plan.narrative = render_template(plan, rows)
        plan.narrative_source = "template"
    api_key = os.environ.get("VULNGUARD_LLM_API_KEY", "").strip()
    if not api_key:
        return
    try:
        parsed = _call_llm(grouped, api_key)
    except Exception as exc:
        for plan, _rows in grouped:
            plan.narrative += f"\n\n模型接口调用失败，以上为模板说明。原因：{exc}"
        return
    for plan, _rows in grouped:
        text = parsed.get(plan.id)
        if text:
            plan.narrative = text.strip()
            plan.narrative_source = "llm"


def render_template(plan: Plan, findings: list[Finding]) -> str:
    asset = plan.asset
    top = findings[0] if findings else None
    lines = [
        f"### 结论",
        (
            f"{asset.name} 当前版本 {asset.version}，所在位置 {asset.location}，"
            f"暴露面为{exposure_label(asset.exposure)}。本组最高等级为{band_label(plan.band)}。"
            f"{plan.window}。"
        ),
        "",
        "### 优先原因",
    ]
    if top:
        lines.append(top.rationale)
        if top.advisory.condition:
            lines.append(top.advisory.condition)
    lines.append("")
    lines.append("### 涉及条目")
    for finding in findings[:8]:
        cvss = "无 CVSS" if finding.advisory.cvss is None else f"CVSS {finding.advisory.cvss:.1f}"
        kev = "，KEV" if finding.kev else ""
        kind = "生命周期" if finding.advisory.kind == "eol" else finding.vuln_id
        lines.append(f"- {kind}：{finding.advisory.summary}（{cvss}{kev}）")
    extra = len(findings) - 8
    if extra > 0:
        lines.append(f"- 其余 {extra} 条见完整报告。")
    lines.extend(["", "### 建议动作", f"目标：{plan.target_version or '按人工步骤确定'}。"])
    if plan.mode == "manual":
        lines.append("这组变更包含迁移或构建清单修改，工具只给出步骤，不代为执行。")
    else:
        lines.append("其中白名单内的安装命令可以在批准后执行；默认只做预演。")
    lines.extend(["", "### 变更前"])
    lines.extend(f"- {item}" for item in plan.prechecks)
    lines.extend(["", "### 步骤"])
    for index, step in enumerate(plan.steps, start=1):
        label = "人工" if step.manual else "白名单命令"
        lines.append(f"{index}. （{label}）{step.title}：{step.display}")
    lines.extend(["", "### 回滚"])
    lines.extend(f"- {item}" for item in plan.rollback)
    lines.extend(["", "### 验证"])
    lines.extend(f"- {item}" for item in plan.verify)
    lines.append("")
    lines.append("说明由固定模板生成，命令不来自语言模型。")
    return "\n".join(lines)


def _call_llm(grouped: list[tuple[Plan, list[Finding]]], api_key: str) -> dict[str, str]:
    facts = []
    for plan, rows in grouped[:12]:
        facts.append(
            {
                "id": plan.id,
                "asset": plan.asset.name,
                "version": plan.asset.version,
                "ecosystem": plan.asset.ecosystem,
                "exposure": plan.asset.exposure,
                "band": plan.band,
                "target_version": plan.target_version,
                "mode": plan.mode,
                "window": plan.window,
                "steps": [step.display for step in plan.steps],
                "rollback": plan.rollback,
                "findings": [
                    {
                        "id": row.vuln_id,
                        "summary": row.advisory.summary,
                        "cvss": row.advisory.cvss,
                        "kev": row.kev,
                        "epss": row.epss,
                        "condition": row.advisory.condition,
                        "kind": row.advisory.kind,
                    }
                    for row in rows[:8]
                ],
            }
        )
    system = _read(skill_path())
    user = _read(user_prompt_path()).replace("{facts}", json.dumps(facts, ensure_ascii=False, indent=2))
    base = os.environ.get("VULNGUARD_LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("VULNGUARD_LLM_MODEL", "gpt-4o-mini")
    body = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    request = urllib.request.Request(
        f"{base}/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = json.loads(response.read().decode())
    content = payload["choices"][0]["message"]["content"]
    parsed = json.loads(_strip_fence(content))
    result = {}
    for item in parsed.get("plans") or []:
        if item.get("id") and item.get("narrative"):
            result[item["id"]] = str(item["narrative"])
    return result


def _strip_fence(text: str) -> str:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned
        if cleaned.endswith("```"):
            cleaned = cleaned[: cleaned.rfind("```")]
    return cleaned.strip()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")
