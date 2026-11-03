#!/usr/bin/env bash
# 用演示资产生成报告。默认写到 runtime/reports/latest，不改仓库里已提交的样例。
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m vulnguard demo --online
echo
echo "查看报告：runtime/reports/latest/report.md"
echo "打开界面： python3 -m vulnguard serve"
