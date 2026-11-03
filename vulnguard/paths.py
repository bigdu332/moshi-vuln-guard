"""定位仓库根目录与随包数据。"""

from __future__ import annotations

from pathlib import Path


def repo_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in [here.parent, *here.parents]:
        if (candidate / "vulnguard").is_dir() and (candidate / "demo").is_dir():
            return candidate
    return here.parents[1]


def package_data() -> Path:
    return Path(__file__).resolve().parent / "data"


def skill_path() -> Path:
    return repo_root() / "ai-process" / "skills" / "remediation-advisor.md"


def user_prompt_path() -> Path:
    return repo_root() / "ai-process" / "prompts" / "runtime-user.md"
