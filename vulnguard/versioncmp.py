"""版本比较。

Debian 软件包走简化的 Debian 版本算法（epoch、upstream、revision）。
PyPI 走 packaging。其余生态把先行版本号里的连字符视为 Debian 的 '~'，
使 1.0.0-alpha 小于 1.0.0，也使 Go 伪版本能按时间戳比较。
"""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

_EPOCH = re.compile(r"^(\d+):")


def cmp_versions(left: str, right: str, ecosystem: str = "generic") -> int:
    if ecosystem.lower() in {"pypi", "python"}:
        return _cmp_pypi(left, right)
    if _use_debian(left, right, ecosystem):
        return _cmp_debian(left, right)
    return _cmp_debian(_generic(left), _generic(right))


def version_in_range(version: str, spec: dict[str, str], ecosystem: str) -> bool:
    introduced = spec.get("introduced") or "0"
    if introduced in {"0", "0.0.0"} and _use_debian(version, version, ecosystem) is False:
        # 对带 v 前缀或伪版本，"0" 仍应视为下界。
        pass
    if cmp_versions(version, introduced, ecosystem) < 0:
        return False
    fixed = spec.get("fixed")
    if fixed and cmp_versions(version, fixed, ecosystem) >= 0:
        return False
    last_affected = spec.get("last_affected")
    if last_affected and cmp_versions(version, last_affected, ecosystem) > 0:
        return False
    return True


def max_version(versions: list[str], ecosystem: str) -> str | None:
    return _pick(versions, ecosystem, prefer_greater=True)


def min_version(versions: list[str], ecosystem: str) -> str | None:
    return _pick(versions, ecosystem, prefer_greater=False)


def _pick(versions: list[str], ecosystem: str, prefer_greater: bool) -> str | None:
    usable = [item for item in versions if item]
    if not usable:
        return None
    best = usable[0]
    for item in usable[1:]:
        compared = cmp_versions(item, best, ecosystem)
        if prefer_greater and compared > 0:
            best = item
        if not prefer_greater and compared < 0:
            best = item
    return best


def _cmp_pypi(left: str, right: str) -> int:
    try:
        a = Version(_strip_v(left))
        b = Version(_strip_v(right))
    except InvalidVersion:
        return _cmp_debian(_generic(left), _generic(right))
    return (a > b) - (a < b)


def _use_debian(left: str, right: str, ecosystem: str) -> bool:
    if ecosystem.lower() in {"debian", "ubuntu", "alpine", "rpm"}:
        return True
    return bool(_EPOCH.match(left) or _EPOCH.match(right) or "deb" in left or "deb" in right)


def _generic(value: str) -> str:
    text = _strip_v(value.strip())
    if ":" in text:
        return text
    return text.replace("-", "~")


def _strip_v(value: str) -> str:
    text = value.strip()
    if text[:1] in {"v", "V"} and text[1:2].isdigit():
        return text[1:]
    return text


def _split_debian(value: str) -> tuple[int, str, str]:
    text = value.strip()
    epoch = 0
    match = _EPOCH.match(text)
    if match:
        epoch = int(match.group(1))
        text = text[match.end() :]
    if "-" in text:
        upstream, revision = text.rsplit("-", 1)
    else:
        upstream, revision = text, ""
    return epoch, upstream, revision


def _cmp_debian(left: str, right: str) -> int:
    le, lu, lr = _split_debian(left)
    re_, ru, rr = _split_debian(right)
    if le != re_:
        return -1 if le < re_ else 1
    upstream = _cmp_part(lu, ru)
    if upstream != 0:
        return upstream
    return _cmp_part(lr, rr)


def _order(ch: str | None) -> int:
    if ch is None:
        return 0
    if ch == "~":
        return -1
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _cmp_part(left: str, right: str) -> int:
    ia = ib = 0
    while ia < len(left) or ib < len(right):
        while True:
            ca = left[ia] if ia < len(left) and not left[ia].isdigit() else None
            cb = right[ib] if ib < len(right) and not right[ib].isdigit() else None
            if ca is None and cb is None:
                break
            oa, ob = _order(ca), _order(cb)
            if oa != ob:
                return -1 if oa < ob else 1
            if ca is not None:
                ia += 1
            if cb is not None:
                ib += 1
        na = nb = 0
        while ia < len(left) and left[ia].isdigit():
            na = na * 10 + int(left[ia])
            ia += 1
        while ib < len(right) and right[ib].isdigit():
            nb = nb * 10 + int(right[ib])
            ib += 1
        if na != nb:
            return -1 if na < nb else 1
    return 0
