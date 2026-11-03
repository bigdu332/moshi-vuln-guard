"""从本机、fixture、Docker 或 SSH 采集资产。"""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Callable

from vulnguard.models import Asset

Runner = Callable[[list[str]], tuple[int, str, str]]

PRODUCT_NAMES = {
    "nginx": "nginx",
    "redis": "redis",
    "redis-server": "redis",
    "mysql": "mysql",
    "mysql-server": "mysql",
    "mysqld": "mysql",
}

NGINX_RE = re.compile(r"nginx/(\d+\.\d+\.\d+)", re.IGNORECASE)
REDIS_RE = re.compile(r"\bv=(\d+\.\d+\.\d+)")
MYSQL_RE = re.compile(r"(?:Distrib|Ver)\s+(\d+\.\d+\.\d+)")
REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)\s*(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9.*+!_]+)"
)


def collect_fixture(path: Path) -> tuple[list[Asset], list[str], str]:
    root = Path(path)
    host_file = root / "host.json"
    host_info = json.loads(host_file.read_text(encoding="utf-8")) if host_file.exists() else {}
    hostname = host_info.get("hostname", root.name)
    warnings: list[str] = []
    assets: list[Asset] = []
    if (root / "dpkg.tsv").exists():
        assets.extend(_from_dpkg((root / "dpkg.tsv").read_text(encoding="utf-8"), f"fixture:{hostname}", str(root / "dpkg.tsv")))
    if (root / "middleware.txt").exists():
        assets.extend(parse_banners((root / "middleware.txt").read_text(encoding="utf-8"), f"fixture:{hostname}"))
    app = root / "app"
    if app.exists():
        assets.extend(parse_manifest_tree(app, f"fixture:{hostname}"))
    merged = _merge_products(assets)
    _apply_exposure(merged, host_info.get("exposure") or {})
    for asset in merged:
        asset.host = hostname
        if not asset.source:
            asset.source = f"fixture:{hostname}"
    return merged, warnings, hostname


def collect_local(manifest_root: Path, runner: Runner | None = None) -> tuple[list[Asset], list[str], str]:
    run = runner or _subprocess_runner
    warnings: list[str] = []
    assets: list[Asset] = []
    code, out, err = run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"])
    if code == 0 and out.strip():
        assets.extend(_from_dpkg(out, "local", "dpkg-query"))
    else:
        warnings.append("本机没有 dpkg，或 dpkg-query 执行失败，已跳过 Debian 软件包。")
    for argv in (["nginx", "-v"], ["redis-server", "--version"], ["mysql", "--version"], ["mysqld", "--version"]):
        code, out, err = run(argv)
        text = f"{out}\n{err}"
        found = parse_banners(text, "local")
        if found:
            assets.extend(found)
    root = Path(manifest_root)
    if root.exists():
        assets.extend(parse_manifest_tree(root, "local"))
    else:
        warnings.append(f"清单目录不存在：{root}")
    merged = _merge_products(assets)
    for asset in merged:
        asset.host = "localhost"
        asset.exposure = "local" if asset.kind == "os_package" else "internal"
    return merged, warnings, "localhost"


def collect_docker(runner: Runner | None = None) -> tuple[list[Asset], list[str], str]:
    run = runner or _subprocess_runner
    code, out, err = run(["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}"])
    if code != 0:
        raise RuntimeError(err.strip() or "docker ps 失败。当前环境可能没有 Docker 守护进程。")
    warnings: list[str] = []
    assets: list[Asset] = []
    rows = [line for line in out.splitlines() if line.strip()]
    if not rows:
        warnings.append("docker ps 没有返回正在运行的容器。")
    for line in rows:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        cid, name, image = parts[0], parts[1], parts[2]
        source = f"docker:{name}"
        location = f"{name} ({image})"
        for argv in (
            ["nginx", "-v"],
            ["redis-server", "--version"],
            ["mysql", "--version"],
            ["mysqld", "--version"],
        ):
            code, stdout, stderr = run(["docker", "exec", cid, *argv])
            found = parse_banners(f"{stdout}\n{stderr}", source)
            for asset in found:
                asset.location = location
                assets.append(asset)
        code, stdout, stderr = run(["docker", "exec", cid, "dpkg-query", "-W", "-f", "${Package}\t${Version}\n"])
        if code == 0:
            for asset in _from_dpkg(stdout, source, location):
                if asset.product in {"redis", "nginx", "mysql"}:
                    assets.append(asset)
        for manifest in ("/opt/app/requirements.txt", "/opt/app/package.json", "/opt/app/pom.xml", "/opt/app/go.mod"):
            code, stdout, stderr = run(["docker", "exec", cid, "cat", manifest])
            if code == 0 and stdout.strip():
                assets.extend(_parse_manifest_text(Path(manifest).name, stdout, source, location))
    merged = _merge_products(assets)
    for asset in merged:
        asset.host = asset.source.removeprefix("docker:") or "docker"
        if asset.product == "nginx":
            asset.exposure = "internet"
    return merged, warnings, "docker"


def collect_ssh(host: str, user: str | None = None, port: int = 22, runner: Runner | None = None) -> tuple[list[Asset], list[str], str]:
    run = runner or _subprocess_runner
    target = f"{user}@{host}" if user else host
    argv = [
        "ssh",
        "-p",
        str(port),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        target,
        REMOTE_SCRIPT,
    ]
    code, stdout, stderr = run(argv)
    if code != 0:
        raise RuntimeError(stderr.strip() or f"SSH 连接 {target} 失败")
    assets = parse_remote_inventory(stdout, f"ssh:{target}")
    for asset in assets:
        asset.host = host
    return assets, [], host


REMOTE_SCRIPT = r"""
set +e
echo '===DPKG==='
dpkg-query -W -f '${Package}\t${Version}\n' 2>/dev/null
echo '===NGINX==='
nginx -v 2>&1
echo '===REDIS==='
redis-server --version 2>&1
echo '===MYSQL==='
mysql --version 2>&1
mysqld --version 2>&1
echo '===END==='
"""


def parse_remote_inventory(text: str, source: str) -> list[Asset]:
    sections = _sections(text)
    assets: list[Asset] = []
    assets.extend(_from_dpkg(sections.get("DPKG", ""), source, "remote dpkg"))
    banner = "\n".join(sections.get(name, "") for name in ("NGINX", "REDIS", "MYSQL"))
    assets.extend(parse_banners(banner, source))
    return _merge_products(assets)


def parse_banners(text: str, source: str) -> list[Asset]:
    assets: list[Asset] = []
    nginx = NGINX_RE.search(text)
    if nginx:
        assets.append(_product_asset("nginx", nginx.group(1), "generic", source, nginx.group(0)))
    redis = REDIS_RE.search(text)
    if redis:
        assets.append(_product_asset("redis", redis.group(1), "generic", source, redis.group(0)))
    mysql = MYSQL_RE.search(text)
    if mysql:
        assets.append(_product_asset("mysql", mysql.group(1), "generic", source, mysql.group(0)))
    return assets


def parse_manifest_tree(root: Path, source: str) -> list[Asset]:
    assets: list[Asset] = []
    if not root.exists():
        return assets
    names = {"requirements.txt", "package.json", "pom.xml", "go.mod"}
    files = [root] if root.is_file() else [path for path in root.rglob("*") if path.name in names]
    for path in files:
        if path.name not in names or not path.is_file():
            continue
        assets.extend(_parse_manifest_text(path.name, path.read_text(encoding="utf-8"), source, str(path)))
    return assets


def parse_requirements(text: str, source: str, location: str) -> list[Asset]:
    assets: list[Asset] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        match = REQUIREMENT_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        assets.append(
            Asset(
                name=_pypi_name(name),
                version=match.group(2),
                ecosystem="PyPI",
                kind="app_dependency",
                location=location,
                source=source,
                evidence=line,
                product=_pypi_name(name),
            )
        )
    return assets


def parse_package_json(text: str, source: str, location: str) -> list[Asset]:
    data = json.loads(text)
    assets: list[Asset] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, version in (data.get(section) or {}).items():
            cleaned = str(version).lstrip("^~>=< ")
            if not re.match(r"^\d", cleaned):
                continue
            assets.append(
                Asset(
                    name=name.lower(),
                    version=cleaned,
                    ecosystem="npm",
                    kind="app_dependency",
                    location=location,
                    source=source,
                    evidence=f"{section}:{name}@{version}",
                    product=name.lower(),
                )
            )
    return assets


def parse_pom(text: str, source: str, location: str) -> list[Asset]:
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    assets: list[Asset] = []

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    for dependency in root.iter():
        if local(dependency.tag) != "dependency":
            continue
        group = artifact = version = ""
        for child in list(dependency):
            label = local(child.tag)
            if label == "groupId":
                group = (child.text or "").strip()
            elif label == "artifactId":
                artifact = (child.text or "").strip()
            elif label == "version":
                version = (child.text or "").strip()
        if artifact and version and not version.startswith("${"):
            name = f"{group}:{artifact}" if group else artifact
            assets.append(
                Asset(
                    name=name,
                    version=version,
                    ecosystem="Maven",
                    kind="app_dependency",
                    location=location,
                    source=source,
                    evidence=name,
                    product=name,
                )
            )
    return assets


def parse_go_mod(text: str, source: str, location: str) -> list[Asset]:
    assets: list[Asset] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require ") :].strip()
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1]
        if module.startswith("("):
            continue
        assets.append(
            Asset(
                name=module,
                version=version,
                ecosystem="Go",
                kind="app_dependency",
                location=location,
                source=source,
                evidence=f"{module} {version}",
                product=module,
            )
        )
    return assets


def _parse_manifest_text(name: str, text: str, source: str, location: str) -> list[Asset]:
    if name == "requirements.txt":
        return parse_requirements(text, source, location)
    if name == "package.json":
        return parse_package_json(text, source, location)
    if name == "pom.xml":
        return parse_pom(text, source, location)
    if name == "go.mod":
        return parse_go_mod(text, source, location)
    return []


def _from_dpkg(text: str, source: str, location: str) -> list[Asset]:
    assets: list[Asset] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            name, version = line.split("\t", 1)
        else:
            parts = line.split()
            if len(parts) < 2:
                continue
            name, version = parts[0], parts[1]
        product = PRODUCT_NAMES.get(name, name)
        ecosystem = "Debian"
        canonical = product if product in {"nginx", "redis", "mysql"} else name
        assets.append(
            Asset(
                name=canonical,
                version=version.strip(),
                ecosystem=ecosystem,
                kind="middleware" if canonical in {"nginx", "redis", "mysql"} else "os_package",
                location=location,
                source=source,
                evidence=f"{name} {version.strip()}",
                product=product,
            )
        )
    return assets


def _product_asset(name: str, version: str, ecosystem: str, source: str, evidence: str) -> Asset:
    return Asset(
        name=name,
        version=version,
        ecosystem=ecosystem,
        kind="middleware",
        location=evidence,
        source=source,
        evidence=evidence,
        product=name,
    )


def _merge_products(assets: list[Asset]) -> list[Asset]:
    """同一产品若同时有发行版包版本和二进制横幅，保留发行版版本。"""
    chosen: dict[str, Asset] = {}
    order: list[str] = []
    for asset in assets:
        key = asset.product or f"{asset.ecosystem}:{asset.name}"
        if asset.kind == "app_dependency":
            key = asset.key
        if key not in chosen:
            chosen[key] = asset
            order.append(key)
            continue
        current = chosen[key]
        if current.ecosystem == "generic" and asset.ecosystem == "Debian":
            asset.evidence = "；".join(item for item in (asset.evidence, current.evidence) if item)
            chosen[key] = asset
        elif asset.ecosystem == "generic" and current.ecosystem == "Debian":
            current.evidence = "；".join(item for item in (current.evidence, asset.evidence) if item)
        elif asset.key != current.key:
            extra = asset.key
            if extra not in order:
                chosen[extra] = asset
                order.append(extra)
    return [chosen[key] for key in order]


def _apply_exposure(assets: list[Asset], exposure: dict[str, str]) -> None:
    for asset in assets:
        if asset.name in exposure:
            asset.exposure = exposure[asset.name]
        elif asset.product in exposure:
            asset.exposure = exposure[asset.product]


def _pypi_name(name: str) -> str:
    return name.replace("_", "-").lower()


def _sections(text: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current = ""
    for line in text.splitlines():
        if line.startswith("===") and line.endswith("==="):
            current = line.strip("=")
            sections.setdefault(current, [])
            continue
        if current:
            sections[current].append(line)
    return {key: "\n".join(value) for key, value in sections.items()}


def _subprocess_runner(argv: list[str]) -> tuple[int, str, str]:
    import subprocess

    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)
    return completed.returncode, completed.stdout, completed.stderr


def format_command(argv: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in argv)
