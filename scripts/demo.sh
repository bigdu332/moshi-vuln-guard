#!/usr/bin/env bash
# 用演示资产生成报告。在线数据源失败时，程序会改用随包快照。
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m vulnguard demo --online --out artifacts/demo-run
echo
echo "查看报告： artifacts/demo-run/report.md"
echo "打开界面： python3 -m vulnguard serve"
