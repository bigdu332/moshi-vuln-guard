"""生成可复核的更新方案。命令只来自白名单模板，不来自模型输出。"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date

from vulnguard.models import Asset, Finding, Plan, Step
from vulnguard.priority import band_label
from vulnguard.versioncmp import cmp_versions, max_version, min_version

PKG = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
PIN = re.compile(r"^[a-z0-9][a-z0-9+.-]*=[A-Za-z0-9.:+~_-]+$")
PIP = re.compile(r"^[A-Za-z0-9_.\-]+==[A-Za-z0-9.*+!_]+$")
NPM = re.compile(r"^[a-z0-9@/_.\-]+@[A-Za-z0-9.*_-]+$")

# 某些编号不能停在第一个修复版本上。
MINIMUM_UPGRADE = {
    ("Maven", "org.apache.logging.log4j:log4j-core"): "2.17.1",
    ("generic", "nginx"): "1.20.1",
}

WINDOW = {
    "critical": "建议 24 小时内处理",
    "high": "建议 7 天内处理",
    "medium": "建议 30 天内处理",
    "low": "纳入常规补丁窗口",
}


def build_plans(findings: list[Finding]) -> list[Plan]:
    grouped: dict[str, list[Finding]] = {}
    assets: dict[str, Asset] = {}
    for finding in findings:
        grouped.setdefault(finding.asset.key, []).append(finding)
        assets[finding.asset.key] = finding.asset
    plans: list[Plan] = []
    for key, rows in grouped.items():
        rows.sort(key=lambda item: -item.score)
        plans.append(_plan_for(assets[key], rows))
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    plans.sort(key=lambda item: (rank.get(item.band, 9), item.asset.name))
    return plans


def command_hash(steps: list[Step]) -> str:
    payload = [{"display": step.display, "argv": step.argv, "manual": step.manual} for step in steps]
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def argv_allowed(argv: list[str] | None) -> bool:
    if not argv:
        return False
    if len(argv) == 4 and argv[:3] == ["apt-get", "install", "--only-upgrade"] and PKG.match(argv[3]):
        return True
    if len(argv) == 3 and argv[:2] == ["apt-get", "install"] and PIN.match(argv[2]):
        return True
    if len(argv) == 3 and argv[:2] == ["pip", "install"] and PIP.match(argv[2]):
        return True
    if len(argv) == 4 and argv[:3] == ["pip", "install", "--dry-run"] and PIP.match(argv[3]):
        return True
    if len(argv) == 3 and argv[:2] == ["npm", "install"] and NPM.match(argv[2]):
        return True
    return False


def preview(plan: Plan) -> str:
    _require_hash(plan)
    lines = [f"方案 {plan.id} 预演。这一步不会修改系统。", f"目标版本：{plan.target_version or '见人工步骤'}"]
    for index, step in enumerate(plan.steps, start=1):
        if step.manual or not step.argv:
            lines.append(f"{index}. [人工] {step.display}")
            continue
        if not argv_allowed(step.argv):
            lines.append(f"{index}. [拒绝] 命令不在白名单：{step.display}")
            continue
        lines.append(f"{index}. [预演] {' '.join(step.argv)}")
    if plan.rollback:
        lines.append("回滚准备：")
        lines.extend(f"- {item}" for item in plan.rollback)
    return "\n".join(lines)


def execute(plan: Plan, *, approved: bool, allow_apply: bool, runner) -> str:
    _require_hash(plan)
    if plan.status == "rejected":
        raise PermissionError("方案已驳回，不能执行。")
    if not approved or plan.status != "approved":
        raise PermissionError("执行前需要人工批准。")
    transcript = preview(plan)
    if not allow_apply:
        return transcript + "\n[停止] 未设置 VULNGUARD_ALLOW_APPLY=1，没有对系统做任何更改。"
    if plan.mode != "auto_eligible":
        return transcript + "\n[停止] 该方案包含重大变更或人工步骤，工具不代为执行。"
    outputs = [transcript, "[执行] 已获得批准，且允许执行白名单命令。"]
    for step in plan.steps:
        if step.manual or not step.argv:
            outputs.append(f"[跳过人工步骤] {step.display}")
            continue
        if not argv_allowed(step.argv):
            raise PermissionError(f"命令不在白名单：{step.display}")
        code, out, err = runner(step.argv)
        outputs.append(f"[退出码 {code}] {' '.join(step.argv)}")
        if out.strip():
            outputs.append(out.strip())
        if err.strip():
            outputs.append(err.strip())
        if code != 0:
            outputs.append("[中止] 命令失败，请按回滚步骤处理。")
            break
    return "\n".join(outputs)


def _require_hash(plan: Plan) -> None:
    if command_hash(plan.steps) != plan.command_hash:
        raise PermissionError("方案命令已被改动，与生成时的摘要不一致。")


def _plan_for(asset: Asset, findings: list[Finding]) -> Plan:
    top = findings[0]
    target = _target_version(asset, findings)
    mode, steps, rollback = _steps(asset, target, findings)
    window = _window(top)
    prechecks = [
        "确认处于维护窗口，并通知依赖该服务的应用负责人。",
        "记录当前版本、配置路径和最近一次备份位置。",
        "在预发或快照上先走一遍同样的步骤。",
    ]
    if any(item.advisory.condition for item in findings):
        prechecks.append("阅读每条漏洞的适用条件，确认这套部署确实走到了受影响配置。")
    verify = [
        f"版本应变为 {target} 或更新。" if target else "按人工步骤核对版本或迁移结果。",
        "进程能够启动，健康检查和错误日志没有新增异常。",
        "抽查核心业务读写，确认回滚材料仍可使用。",
    ]
    steps_model = steps
    plan_id = "plan-" + _slug(asset.key)
    return Plan(
        id=plan_id,
        asset=asset,
        title=f"更新 {asset.name} {asset.version}",
        band=top.band,
        target_version=target,
        mode=mode,
        prechecks=prechecks,
        steps=steps_model,
        rollback=rollback,
        verify=verify,
        window=window,
        finding_ids=[item.id for item in findings],
        command_hash=command_hash(steps_model),
    )


def _target_version(asset: Asset, findings: list[Finding]) -> str | None:
    """每个条目先取高于现状的最低修复版本，再取其中最大者，从而一次升级盖住全部条目。"""
    ceilings: list[str] = []
    for finding in findings:
        higher = [item for item in finding.fixed_versions if cmp_versions(asset.version, item, asset.ecosystem) < 0]
        ceiling = min_version(higher, asset.ecosystem)
        if ceiling:
            ceilings.append(ceiling)
    best = max_version(ceilings, asset.ecosystem)
    minimum = MINIMUM_UPGRADE.get((asset.ecosystem, asset.name))
    if asset.name == "org.apache.logging.log4j:log4j-core":
        minimum = MINIMUM_UPGRADE[("Maven", asset.name)]
    if minimum and (best is None or cmp_versions(best, minimum, asset.ecosystem) < 0):
        if cmp_versions(asset.version, minimum, asset.ecosystem) < 0:
            best = minimum
    if asset.product == "nginx":
        return "不低于 1.20.1 的现行 stable"
    if asset.product == "mysql":
        return "8.4 LTS"
    if asset.product == "redis" and asset.ecosystem == "Debian":
        return "5:5.0.14-1+deb10u2（buster 安全更新；随后规划离开 5.0）"
    if asset.product == "redis":
        return "仍在维护的上游版本（短期不低于 5.0.14）"
    return best


def _steps(asset: Asset, target: str | None, findings: list[Finding]) -> tuple[str, list[Step], list[str]]:
    notes = [item.advisory.condition for item in findings if item.advisory.condition]
    if asset.ecosystem == "Debian" and asset.product == "redis":
        pkg = "redis-server"
        upgrade = ["apt-get", "install", "--only-upgrade", pkg]
        pin = f"{pkg}={asset.version}"
        steps = [
            Step("备份 RDB/AOF 与 redis.conf", "cp /var/lib/redis 与 /etc/redis 到维护目录", manual=True),
            Step("安装 Debian 安全更新", "apt-get install --only-upgrade redis-server", manual=False, argv=upgrade),
            Step("离开已经停止维护的 5.0 分支", "另排窗口迁移到仍在维护的主版本，本工具不自动做大版本迁移。", manual=True),
        ]
        rollback = [f"apt-get install {pin}", "用备份的 RDB/AOF 恢复数据"]
        return "auto_eligible", steps, rollback
    if asset.ecosystem == "PyPI" and target and " " not in target and not _major_jump(asset.version, target):
        spec = f"{asset.name}=={target}"
        steps = [
            Step("冻结当前环境", "pip freeze > requirements.freeze.bak", manual=True),
            Step("升级锁定版本", f"pip install {spec}", manual=False, argv=["pip", "install", spec]),
        ]
        rollback = [f"pip install {asset.name}=={asset.version}"]
        return "auto_eligible", steps, rollback
    if asset.ecosystem == "npm" and target and re.fullmatch(r"[A-Za-z0-9.*_-]+", target) and not _major_jump(asset.version, target):
        spec = f"{asset.name}@{target}"
        steps = [
            Step("确认锁文件已提交", "检查 package-lock.json 或 yarn.lock 已在版本库中", manual=True),
            Step("升级 npm 依赖", f"npm install {spec}", manual=False, argv=["npm", "install", spec]),
        ]
        rollback = [f"npm install {asset.name}@{asset.version}"]
        return "auto_eligible", steps, rollback
    if asset.product == "nginx":
        steps = [
            Step(
                "升级到现行 stable",
                "将 nginx 升到仍在接收安全修复的 stable，且不低于 1.20.1。先备份 nginx.conf、证书和站点配置。",
                manual=True,
            ),
            Step("核对 resolver", "若配置里没有 resolver，CVE-2021-23017 的可利用性会低很多，但仍应离开 1.18。", manual=True),
        ]
        rollback = ["用备份的配置和原版本软件包重新拉起 nginx"]
        return "manual", steps, rollback
    if asset.ecosystem == "Maven":
        steps = [
            Step(
                "修改构建清单",
                f"把 {asset.name} 从 {asset.version} 改到 {target or '安全版本'}，然后重新构建并扫描依赖树。",
                manual=True,
            ),
            Step("回归日志与启动", "在预发启动应用，确认没有再加载旧的 log4j-core。", manual=True),
        ]
        rollback = ["用版本库还原 pom.xml / build 文件并重新部署上一构建产物"]
        return "manual", steps, rollback
    steps = [
        Step(
            "按发行版或供应商流程升级",
            f"将 {asset.name} 从 {asset.version} 升级到 {target or '仍在维护的版本'}。先备份配置和数据。",
            manual=True,
        )
    ]
    if notes:
        steps.append(Step("核对适用条件", notes[0], manual=True))
    rollback = ["保留升级前的软件包版本、配置和数据快照，确认可以按原版本拉起"]
    return "manual", steps, rollback


def _window(finding: Finding) -> str:
    if finding.kev and finding.kev_due:
        try:
            due = date.fromisoformat(finding.kev_due)
        except ValueError:
            due = None
        if due and due < date.today():
            return f"CISA KEV 截止日期 {finding.kev_due} 已过，建议 24 小时内处理"
        if due:
            return f"列入 CISA KEV，截止日期 {finding.kev_due}"
    if finding.kev:
        return "列入 CISA KEV，建议 24 小时内处理"
    return WINDOW.get(finding.band, "纳入常规补丁窗口")


def _major_jump(current: str, target: str) -> bool:
    return _major(target) > _major(current)


def _major(version: str) -> int:
    text = version[1:] if version[:1] in {"v", "V"} and len(version) > 1 and version[1].isdigit() else version
    digits = ""
    for char in text:
        if char.isdigit():
            digits += char
        else:
            break
    return int(digits) if digits else 0


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "plan"


def band_text(band: str) -> str:
    return band_label(band)
