"""CVSS v3.0 / v3.1 基础分。只实现公开规范中的 base score。"""

from __future__ import annotations

import math
import re

_METRIC = re.compile(r"([A-Z]+):([A-Z])")

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}


def score_vector(vector: str) -> float | None:
    text = vector.strip()
    if not text.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    parts = dict(_METRIC.findall(text))
    needed = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not needed <= parts.keys():
        return None
    scope = parts["S"]
    if scope not in {"U", "C"}:
        return None
    try:
        exploitability = 8.22 * _AV[parts["AV"]] * _AC[parts["AC"]] * _PR[scope][parts["PR"]] * _UI[parts["UI"]]
        impact_sub = 1 - (1 - _CIA[parts["C"]]) * (1 - _CIA[parts["I"]]) * (1 - _CIA[parts["A"]])
    except KeyError:
        return None
    if scope == "U":
        impact = 6.42 * impact_sub
    else:
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15
    if impact <= 0:
        return 0.0
    if scope == "U":
        raw = min(impact + exploitability, 10)
    else:
        raw = min(1.08 * (impact + exploitability), 10)
    return _roundup(raw)


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def estimate_from_label(label: str | None) -> float | None:
    if not label:
        return None
    table = {
        "CRITICAL": 9.5,
        "HIGH": 7.5,
        "MODERATE": 5.5,
        "MEDIUM": 5.5,
        "LOW": 3.0,
    }
    return table.get(label.upper())


def _roundup(value: float) -> float:
    """CVSS v3 Roundup：保留到 0.1，并向上进位。"""
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0
