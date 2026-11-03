"""把 CVSS、KEV、EPSS 和暴露面合成一个可解释的优先级。"""

from __future__ import annotations

EXPOSURE_FACTOR = {"internet": 1.0, "internal": 0.85, "local": 0.70}
EXPOSURE_LABEL = {"internet": "互联网", "internal": "内网", "local": "仅本机"}
BAND_LABEL = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}

# 权重写在这里，设计文档与界面共用同一套数字。
WEIGHT_CVSS = 1.0
WEIGHT_KEV = 0.25
WEIGHT_EPSS = 0.15


def prioritize(
    cvss: float | None,
    *,
    kev: bool,
    epss: float | None,
    exposure: str,
) -> tuple[float, str, str]:
    exposure_factor = EXPOSURE_FACTOR.get(exposure, EXPOSURE_FACTOR["internal"])
    base_cvss = 0.0 if cvss is None else max(0.0, min(10.0, cvss))
    cvss_term = base_cvss / 10.0
    kev_term = WEIGHT_KEV if kev else 0.0
    if epss is None:
        epss_term = 0.0
        epss_text = "EPSS 未取得，这项暂不加减分"
    else:
        bounded = max(0.0, min(1.0, epss))
        epss_term = WEIGHT_EPSS * bounded
        epss_text = f"EPSS {bounded:.4f}，贡献 {epss_term:.4f}"
    combined = min(1.0, cvss_term + kev_term + epss_term)
    score = round(combined * exposure_factor, 4)
    forced = kev and base_cvss >= 7.0
    if forced:
        score = max(score, 0.85)
        band = "critical"
    elif score >= 0.85:
        band = "critical"
    elif score >= 0.60:
        band = "high"
    elif score >= 0.35:
        band = "medium"
    else:
        band = "low"
    cvss_text = "无 CVSS" if cvss is None else f"CVSS {base_cvss:.1f}"
    kev_text = "在 CISA KEV 中，贡献 0.25" if kev else "不在 CISA KEV"
    rationale = (
        f"{cvss_text}，归一化 {cvss_term:.2f}；{kev_text}；{epss_text}；"
        f"暴露面为{EXPOSURE_LABEL.get(exposure, exposure)}，系数 {exposure_factor:.2f}；"
        f"综合分 {score:.4f}，等级为{BAND_LABEL[band]}。"
    )
    if forced:
        rationale += "触发规则：KEV 且 CVSS 不低于 7，等级至少为严重。"
    return score, band, rationale


def band_label(band: str) -> str:
    return BAND_LABEL.get(band, band)


def exposure_label(exposure: str) -> str:
    return EXPOSURE_LABEL.get(exposure, exposure)
