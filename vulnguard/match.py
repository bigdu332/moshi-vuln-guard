"""把资产对照到公告、生命周期、KEV 和 EPSS。"""

from __future__ import annotations

from vulnguard.feeds import FeedSet
from vulnguard.models import Advisory, Asset, Finding, PackageRange
from vulnguard.priority import prioritize
from vulnguard.versioncmp import version_in_range

_ECOSYSTEM_ALIAS = {
    "pypi": "pypi",
    "python": "pypi",
    "npm": "npm",
    "maven": "maven",
    "go": "go",
    "debian": "debian",
    "generic": "generic",
}


def match_assets(assets: list[Asset], feeds: FeedSet) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for asset in assets:
        if asset.kind == "os_package" and asset.product not in {"nginx", "redis", "mysql"}:
            continue
        for advisory in feeds.advisories:
            if not _applies(asset, advisory):
                continue
            canonical = advisory.canonical_id()
            marker = (asset.key, canonical)
            if marker in seen:
                continue
            seen.add(marker)
            findings.append(_to_finding(asset, advisory, feeds))
    findings.sort(key=lambda item: (-item.score, item.vuln_id, item.asset.name))
    return findings


def _applies(asset: Asset, advisory: Advisory) -> bool:
    for package in advisory.packages:
        if not _name_match(asset, package):
            continue
        if not _ecosystem_match(asset.ecosystem, package.ecosystem, advisory.kind):
            continue
        compare_as = "Debian" if asset.ecosystem.lower() == "debian" else package.ecosystem
        for spec in package.ranges:
            if version_in_range(asset.version, spec, compare_as):
                return True
    return False


def _name_match(asset: Asset, package: PackageRange) -> bool:
    left = asset.name.lower()
    right = package.name.lower()
    if left == right:
        return True
    if asset.product and asset.product.lower() == right:
        return True
    return False


def _ecosystem_match(asset_ecosystem: str, package_ecosystem: str, kind: str) -> bool:
    left = _ECOSYSTEM_ALIAS.get(asset_ecosystem.lower(), asset_ecosystem.lower())
    right = _ECOSYSTEM_ALIAS.get(package_ecosystem.lower(), package_ecosystem.lower())
    if left == right:
        return True
    # 发行版包可以对照上游版本公告，发行版特有公告则要求生态一致。
    if right == "generic" and left in {"debian", "ubuntu", "rpm", "alpine"}:
        return True
    return False


def _to_finding(asset: Asset, advisory: Advisory, feeds: FeedSet) -> Finding:
    aliases = advisory.aliases_all()
    kev_row = feeds.lookup_kev(advisory.canonical_id(), aliases)
    kev = bool(kev_row) or bool(advisory.kev)
    if feeds.status.get("kev") == "live":
        kev = bool(kev_row) or bool(advisory.kev and advisory.kind == "eol")
        if advisory.kev and not kev_row and advisory.kind == "vulnerability":
            # 在线目录成功时以目录为准；目录没有则不沿用可能过期的标记。
            kev = bool(kev_row)
    epss_row = feeds.lookup_epss(advisory.canonical_id(), aliases) or {}
    epss = epss_row.get("epss")
    score, band, rationale = prioritize(advisory.cvss, kev=kev and advisory.kind != "eol", epss=epss, exposure=asset.exposure)
    if advisory.kind == "eol":
        score, band, rationale = prioritize(advisory.cvss, kev=False, epss=None, exposure=asset.exposure)
        rationale = "生命周期项，使用维护风险分代替 CVSS。" + rationale
    fixed: list[str] = []
    for package in advisory.packages:
        if _name_match(asset, package):
            fixed.extend(package.fixed_versions)
    return Finding(
        asset=asset,
        advisory=advisory,
        score=score,
        band=band,
        rationale=rationale,
        kev=kev if advisory.kind != "eol" else False,
        kev_due=(kev_row or {}).get("due") or None,
        kev_name=(kev_row or {}).get("name") or "",
        epss=epss,
        epss_percentile=epss_row.get("percentile"),
        fixed_versions=_unique(fixed),
    )


def _unique(items: list[str]) -> list[str]:
    result = []
    for item in items:
        if item and item not in result:
            result.append(item)
    return result
