"""巡检用到的数据结构。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


def _slug(text: str) -> str:
    keep = []
    for ch in text.lower():
        if ch.isalnum():
            keep.append(ch)
        elif ch in {":", "/", "@", ".", "_", "-"}:
            keep.append("-")
    slug = "".join(keep).strip("-")
    return slug or "item"


@dataclass
class Asset:
    name: str
    version: str
    ecosystem: str
    kind: str
    location: str
    exposure: str = "internal"
    host: str = ""
    source: str = ""
    evidence: str = ""
    product: str = ""

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["key"] = self.key
        return data


@dataclass
class PackageRange:
    ecosystem: str
    name: str
    ranges: list[dict[str, str]] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)


@dataclass
class Advisory:
    id: str
    summary: str
    details: str = ""
    cvss: float | None = None
    cvss_estimated: bool = False
    severity: str = "UNKNOWN"
    aliases: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    packages: list[PackageRange] = field(default_factory=list)
    source: str = "curated"
    condition: str = ""
    kev: bool | None = None
    kind: str = "vulnerability"

    def aliases_all(self) -> list[str]:
        found = []
        for item in [self.id, *self.aliases]:
            if item and item not in found:
                found.append(item)
        return found

    def canonical_id(self) -> str:
        for item in self.aliases_all():
            if item.startswith("CVE-"):
                return item
        return self.id


@dataclass
class Finding:
    asset: Asset
    advisory: Advisory
    score: float
    band: str
    rationale: str
    kev: bool = False
    kev_due: str | None = None
    kev_name: str = ""
    epss: float | None = None
    epss_percentile: float | None = None
    fixed_versions: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        return _slug(f"{self.asset.key}-{self.advisory.canonical_id()}")

    @property
    def vuln_id(self) -> str:
        return self.advisory.canonical_id()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "vuln_id": self.vuln_id,
            "aliases": self.advisory.aliases_all(),
            "summary": self.advisory.summary,
            "details": self.advisory.details,
            "cvss": self.advisory.cvss,
            "cvss_estimated": self.advisory.cvss_estimated,
            "severity": self.advisory.severity,
            "condition": self.advisory.condition,
            "kind": self.advisory.kind,
            "source": self.advisory.source,
            "references": self.advisory.references,
            "kev": self.kev,
            "kev_due": self.kev_due,
            "kev_name": self.kev_name,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "score": self.score,
            "band": self.band,
            "rationale": self.rationale,
            "fixed_versions": self.fixed_versions,
            "asset": self.asset.to_dict(),
        }


@dataclass
class Step:
    title: str
    display: str
    manual: bool = True
    argv: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Plan:
    id: str
    asset: Asset
    title: str
    band: str
    target_version: str | None
    mode: str
    prechecks: list[str]
    steps: list[Step]
    rollback: list[str]
    verify: list[str]
    window: str
    finding_ids: list[str]
    command_hash: str
    narrative: str = ""
    narrative_source: str = "template"
    status: str = "pending"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["asset"] = self.asset.to_dict()
        data["steps"] = [step.to_dict() for step in self.steps]
        return data


@dataclass
class ScanResult:
    id: str
    created_at: str
    source: str
    target: str
    host: str
    assets: list[Asset]
    findings: list[Finding]
    plans: list[Plan]
    warnings: list[str] = field(default_factory=list)
    feeds: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "source": self.source,
            "target": self.target,
            "host": self.host,
            "warnings": self.warnings,
            "feeds": self.feeds,
            "assets": [asset.to_dict() for asset in self.assets],
            "findings": [finding.to_dict() for finding in self.findings],
            "plans": [plan.to_dict() for plan in self.plans],
        }
