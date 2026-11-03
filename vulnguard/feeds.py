"""读取策展公告、OSV、CISA KEV 与 EPSS。在线失败时回落到随包快照。"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from vulnguard.cvss import estimate_from_label, score_vector, severity_from_score
from vulnguard.models import Advisory, PackageRange
from vulnguard.paths import package_data

OSV_QUERY = "https://api.osv.dev/v1/query"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

DEMO_QUERIES = [
    ("PyPI", "pyyaml", "5.3.1"),
    ("PyPI", "jinja2", "2.11.2"),
    ("PyPI", "itsdangerous", "2.2.0"),
    ("npm", "lodash", "4.17.20"),
    ("npm", "minimist", "1.2.5"),
    ("npm", "express", "4.17.1"),
    ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
    ("Go", "gopkg.in/yaml.v3", "v3.0.0-20210107192922-496545a6307b"),
]


class FeedSet:
    def __init__(self) -> None:
        self.advisories: list[Advisory] = []
        self.kev: dict[str, dict] = {}
        self.epss: dict[str, dict] = {}
        self.status = {"osv": "off", "kev": "off", "epss": "off", "curated": "off"}

    def lookup_kev(self, vuln_id: str, aliases: list[str]) -> dict | None:
        for item in [vuln_id, *aliases]:
            if item in self.kev:
                return self.kev[item]
        return None

    def lookup_epss(self, vuln_id: str, aliases: list[str]) -> dict | None:
        for item in [vuln_id, *aliases]:
            if item in self.epss:
                return self.epss[item]
        return None


def load_feeds(*, online: bool = True, timeout: float = 25) -> FeedSet:
    feeds = FeedSet()
    feeds.advisories.extend(load_curated())
    feeds.status["curated"] = "snapshot"
    snapshot = _read_json(package_data() / "osv_snapshot.json")
    if snapshot:
        feeds.advisories.extend(advisories_from_snapshot(snapshot))
        feeds.status["osv"] = "snapshot"
    kev_snapshot = _read_json(package_data() / "kev_snapshot.json")
    if kev_snapshot:
        feeds.kev = kev_snapshot.get("items") or {}
        feeds.status["kev"] = "snapshot"
    epss_snapshot = _read_json(package_data() / "epss_snapshot.json")
    if epss_snapshot:
        feeds.epss = epss_snapshot.get("items") or {}
        feeds.status["epss"] = "snapshot"
    if online:
        _refresh_live(feeds, timeout)
    feeds.advisories = dedupe_advisories(feeds.advisories)
    return feeds


def _refresh_live(feeds: FeedSet, timeout: float) -> None:
    try:
        live = query_osv_packages(DEMO_QUERIES, timeout=timeout)
        if live:
            feeds.advisories = _merge_advisories(load_curated(), live)
            feeds.status["osv"] = "live"
    except Exception:
        pass
    try:
        live_kev = fetch_kev(timeout=timeout)
        if live_kev:
            feeds.kev = live_kev
            feeds.status["kev"] = "live"
    except Exception:
        pass
    cves = sorted({item.canonical_id() for item in feeds.advisories if item.canonical_id().startswith("CVE-")})
    try:
        live_epss = fetch_epss(cves, timeout=timeout)
        if live_epss:
            feeds.epss = live_epss
            feeds.status["epss"] = "live"
    except Exception:
        pass


def dedupe_advisories(items: list[Advisory]) -> list[Advisory]:
    """同一 CVE 可能同时有 GHSA 和 GO/PYSEC 记录，保留有 CVSS 的那条并合并修复版本。"""
    chosen: dict[tuple[str, str], Advisory] = {}
    order: list[tuple[str, str]] = []
    for item in items:
        key = (item.kind, item.canonical_id())
        if key not in chosen:
            chosen[key] = item
            order.append(key)
            continue
        chosen[key] = _richer(chosen[key], item)
    return [chosen[key] for key in order]


def _richer(current: Advisory, incoming: Advisory) -> Advisory:
    primary, secondary = current, incoming
    if current.cvss is None and incoming.cvss is not None:
        primary, secondary = incoming, current
    elif (
        current.cvss is not None
        and incoming.cvss is not None
        and incoming.cvss > current.cvss
        and current.cvss_estimated
        and not incoming.cvss_estimated
    ):
        primary, secondary = incoming, current
    aliases: list[str] = []
    for item in primary.aliases_all() + secondary.aliases_all():
        if item not in aliases and item != primary.id:
            aliases.append(item)
    primary.aliases = aliases
    for ref in secondary.references:
        if ref not in primary.references:
            primary.references.append(ref)
    if _is_chinese(secondary.summary) and not _is_chinese(primary.summary):
        primary.summary = secondary.summary
        primary.details = secondary.details or primary.details
        primary.condition = secondary.condition or primary.condition
    packages = {(package.ecosystem.lower(), package.name.lower()): package for package in primary.packages}
    for package in secondary.packages:
        key = (package.ecosystem.lower(), package.name.lower())
        if key not in packages:
            primary.packages.append(package)
            packages[key] = package
            continue
        target = packages[key]
        for fixed in package.fixed_versions:
            if fixed not in target.fixed_versions:
                target.fixed_versions.append(fixed)
        if not target.ranges and package.ranges:
            target.ranges = package.ranges
    if secondary.kev:
        primary.kev = True
    return primary


def load_curated() -> list[Advisory]:
    raw = json.loads((package_data() / "advisories.json").read_text(encoding="utf-8"))
    advisories = [_advisory_from_dict(item, source="curated") for item in raw.get("vulns") or []]
    eol = json.loads((package_data() / "eol.json").read_text(encoding="utf-8"))
    for item in eol.get("items") or []:
        advisories.append(
            Advisory(
                id=item["id"],
                summary=item["summary"],
                details=item.get("details") or "",
                cvss=float(item.get("cvss_equivalent") or 0),
                severity="MEDIUM",
                references=item.get("references") or [],
                packages=[
                    PackageRange(
                        ecosystem="generic",
                        name=item["name"],
                        ranges=item.get("ranges") or [],
                        fixed_versions=[],
                    ),
                    PackageRange(
                        ecosystem="Debian",
                        name=item["name"],
                        ranges=item.get("ranges") or [],
                        fixed_versions=[],
                    ),
                ],
                source="eol",
                condition=item.get("recommendation") or "",
                kind="eol",
            )
        )
    return advisories


def advisories_from_snapshot(payload: dict) -> list[Advisory]:
    return [_advisory_from_dict(item, source=item.get("source") or "osv") for item in payload.get("vulns") or []]


def query_osv_packages(queries: list[tuple[str, str, str]], timeout: float = 25) -> list[Advisory]:
    found: list[Advisory] = []
    errors: list[str] = []
    for ecosystem, name, version in queries:
        body = json.dumps({"package": {"ecosystem": ecosystem, "name": name}, "version": version}).encode()
        request = urllib.request.Request(
            OSV_QUERY,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "vulnguard-demo"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode())
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{ecosystem}:{name}: {exc}")
            continue
        for vuln in payload.get("vulns") or []:
            advisory = advisory_from_osv(vuln, ecosystem, name)
            if advisory:
                found.append(advisory)
    if errors and not found:
        raise RuntimeError("; ".join(errors))
    return found


def advisory_from_osv(vuln: dict, ecosystem: str, name: str) -> Advisory | None:
    packages: list[PackageRange] = []
    fixed: list[str] = []
    for affected in vuln.get("affected") or []:
        package = affected.get("package") or {}
        pname = (package.get("name") or "").lower()
        if pname and pname != name.lower():
            continue
        ranges = []
        for spec in affected.get("ranges") or []:
            if spec.get("type") not in {None, "ECOSYSTEM", "SEMVER"}:
                continue
            events = {}
            introduced = None
            for event in spec.get("events") or []:
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event and introduced is not None:
                    ranges.append({"introduced": introduced, "fixed": event["fixed"]})
                    fixed.append(event["fixed"])
                    introduced = None
                elif "last_affected" in event and introduced is not None:
                    ranges.append({"introduced": introduced, "last_affected": event["last_affected"]})
                    introduced = None
            if introduced is not None:
                ranges.append({"introduced": introduced})
        if ranges:
            packages.append(
                PackageRange(
                    ecosystem=package.get("ecosystem") or ecosystem,
                    name=package.get("name") or name,
                    ranges=ranges,
                    fixed_versions=fixed[:],
                )
            )
    if not packages:
        packages.append(PackageRange(ecosystem=ecosystem, name=name, ranges=[{"introduced": "0"}], fixed_versions=[]))
    cvss, estimated = _cvss_from_osv(vuln)
    summary = vuln.get("summary") or vuln.get("details") or vuln.get("id")
    details = (vuln.get("details") or "")[:1200]
    return Advisory(
        id=vuln.get("id") or "UNKNOWN",
        summary=summary[:300],
        details=details,
        cvss=cvss,
        cvss_estimated=estimated,
        severity=severity_from_score(cvss),
        aliases=list(vuln.get("aliases") or []),
        references=[ref.get("url") for ref in (vuln.get("references") or []) if ref.get("url")][:6],
        packages=packages,
        source="osv",
    )


def fetch_kev(timeout: float = 25) -> dict[str, dict]:
    request = urllib.request.Request(KEV_URL, headers={"User-Agent": "vulnguard-demo"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode())
    items = {}
    for entry in payload.get("vulnerabilities") or []:
        cve = entry.get("cveID")
        if not cve:
            continue
        items[cve] = {
            "name": entry.get("vulnerabilityName") or "",
            "due": entry.get("dueDate") or "",
            "description": (entry.get("shortDescription") or "")[:400],
        }
    return items


def fetch_epss(cves: list[str], timeout: float = 25) -> dict[str, dict]:
    items: dict[str, dict] = {}
    for offset in range(0, len(cves), 80):
        chunk = cves[offset : offset + 80]
        if not chunk:
            continue
        url = EPSS_URL + "?cve=" + ",".join(chunk)
        request = urllib.request.Request(url, headers={"User-Agent": "vulnguard-demo"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode())
        for row in payload.get("data") or []:
            cve = row.get("cve")
            if not cve:
                continue
            items[cve] = {
                "epss": float(row["epss"]) if row.get("epss") not in (None, "") else None,
                "percentile": float(row["percentile"]) if row.get("percentile") not in (None, "") else None,
            }
    return items


def refresh_snapshots(timeout: float = 40) -> dict[str, str]:
    """拉取公开数据并写入随包快照，供离线演示复现。"""
    advisories = query_osv_packages(DEMO_QUERIES, timeout=timeout)
    kev = fetch_kev(timeout=timeout)
    cves = sorted({item.canonical_id() for item in advisories if item.canonical_id().startswith("CVE-")})
    for curated in load_curated():
        if curated.canonical_id().startswith("CVE-") and curated.canonical_id() not in cves:
            cves.append(curated.canonical_id())
    epss = fetch_epss(cves, timeout=timeout)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = package_data()
    _write_json(data / "osv_snapshot.json", {"fetched_at": stamp, "source": OSV_QUERY, "vulns": [_dump_advisory(item) for item in advisories]})
    relevant_kev = {cve: kev[cve] for cve in cves if cve in kev}
    # 保留策展里已声明的 KEV，即使目录暂缺。
    for curated in load_curated():
        if curated.kev and curated.canonical_id() not in relevant_kev:
            relevant_kev[curated.canonical_id()] = {"name": curated.summary, "due": "", "description": curated.summary}
    _write_json(
        data / "kev_snapshot.json",
        {"fetched_at": stamp, "source": KEV_URL, "catalog_size": len(kev), "items": relevant_kev},
    )
    _write_json(data / "epss_snapshot.json", {"fetched_at": stamp, "source": EPSS_URL, "items": epss})
    return {"osv": str(len(advisories)), "kev": str(len(relevant_kev)), "epss": str(len(epss)), "fetched_at": stamp}


def _cvss_from_osv(vuln: dict) -> tuple[float | None, bool]:
    for item in vuln.get("severity") or []:
        if item.get("type") in {"CVSS_V3", "CVSS_V31", "CVSS_V30"} or str(item.get("score", "")).startswith("CVSS:3"):
            score = score_vector(str(item.get("score") or ""))
            if score is not None:
                return score, False
    database = vuln.get("database_specific") or {}
    estimated = estimate_from_label(str(database.get("severity") or ""))
    if estimated is not None:
        return estimated, True
    return None, False


def _advisory_from_dict(item: dict, source: str) -> Advisory:
    packages = []
    for package in item.get("packages") or []:
        packages.append(
            PackageRange(
                ecosystem=package.get("ecosystem") or "generic",
                name=package.get("name") or "",
                ranges=package.get("ranges") or [],
                fixed_versions=package.get("fixed_versions") or [],
            )
        )
    return Advisory(
        id=item["id"],
        summary=item.get("summary") or item["id"],
        details=item.get("details") or "",
        cvss=item.get("cvss"),
        cvss_estimated=bool(item.get("cvss_estimated")),
        severity=item.get("severity") or severity_from_score(item.get("cvss")),
        aliases=item.get("aliases") or [],
        references=item.get("references") or [],
        packages=packages,
        source=item.get("source") or source,
        condition=item.get("condition") or "",
        kev=item.get("kev"),
        kind=item.get("kind") or "vulnerability",
    )


def _dump_advisory(item: Advisory) -> dict:
    return {
        "id": item.id,
        "summary": item.summary,
        "details": item.details,
        "cvss": item.cvss,
        "cvss_estimated": item.cvss_estimated,
        "severity": item.severity,
        "aliases": item.aliases,
        "references": item.references,
        "condition": item.condition,
        "source": item.source,
        "kind": item.kind,
        "packages": [
            {
                "ecosystem": package.ecosystem,
                "name": package.name,
                "ranges": package.ranges,
                "fixed_versions": package.fixed_versions,
            }
            for package in item.packages
        ],
    }


def _merge_advisories(curated: list[Advisory], live: list[Advisory]) -> list[Advisory]:
    """在线结果优先，策展条目补上在线结果没有的编号，并保留策展中的中文说明。"""
    by_id: dict[str, Advisory] = {}
    for item in live:
        key = item.canonical_id()
        by_id[key] = item if key not in by_id else _richer(by_id[key], item)
    for item in curated:
        key = item.canonical_id()
        if key not in by_id:
            by_id[key] = item
            continue
        current = by_id[key]
        if item.source == "curated" and item.summary and _is_chinese(item.summary):
            current.summary = item.summary
            current.details = item.details or current.details
            current.condition = item.condition or current.condition
            if item.cvss is not None and current.cvss is None:
                current.cvss = item.cvss
            if item.kev:
                current.kev = True
        if item.kind == "eol":
            by_id[item.id] = item
    eol = [item for item in curated if item.kind == "eol"]
    others = [item for item in by_id.values() if item.kind != "eol"]
    return others + eol


def _is_chinese(text: str) -> bool:
    return any("\u4e00" <= ch <= "\u9fff" for ch in text)


def _read_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def silent_url_error(exc: Exception) -> str:
    if isinstance(exc, urllib.error.URLError):
        return str(exc.reason)
    return str(exc)
