# VulnGuard 漏洞守卫

对照已经公开的漏洞清单，检查一套正在运行的系统，定期给出更新建议，并在人工确认后辅助走更新流程。这是上海魔拾科技笔试的可演示成品。界面、报告和设计文档都是中文。

## 已知局限

- 操作系统清单以 Debian/dpkg 为主。rpm 与 apk 已能只读采集；匹配仍把 nginx、Redis、MySQL 当作中间件，其余系统包不逐包请求 OSV。
- Trivy 的 JSON 只作为第二意见附在报告里，不替换 OSV 主路径。Grype、Syft、osv-scanner 仍只检测是否安装，不解析输出。
- 默认可复现路径是 `demo/lab`。`docker compose` 需要本机有 Docker；官方 Redis 镜像不会套用 Debian 特有的 CVE-2022-0543。
- Web 界面没有登录和鉴权，只适合本机演示。

## 它做什么

1. 采集资产：本机 dpkg，以及存在时的 rpm、apk；中间件版本；应用清单（`requirements.txt`、`package.json`、`pom.xml`、`go.mod`）。也可以从 SSH 或 Docker 容器读取。
2. 对照公开数据：OSV.dev、随包策展公告、CISA KEV、EPSS。网络不可用时使用 2026-11-03 的快照。
3. 排出优先级：CVSS、是否在 KEV、EPSS、暴露面，并写出计算过程。
4. 生成更新方案：变更前检查、步骤、回滚和验证。说明可以由兼容 OpenAI 的接口生成；没有密钥时使用固定模板，演示不受影响。
5. 默认只预演。批准后，只有白名单里的命令才可能执行，并且还要打开 `VULNGUARD_ALLOW_APPLY=1`。

## 快速开始

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m vulnguard demo --online
python3 -m vulnguard serve
```

浏览器打开 http://127.0.0.1:8000 。

`--online` 会访问 OSV、CISA KEV 和 FIRST EPSS。访问失败时自动改用 `vulnguard/data/` 里的快照，命令仍然成功。只想离线复现时去掉 `--online`。

`vulnguard demo` 和 `vulnguard scan` 默认把报告写到 `runtime/reports/latest/`。这个目录在 `.gitignore` 里，重复演示不会改动已提交文件。仓库里给阅卷看的样例仍在 `artifacts/demo-run/`，界面截图在 `artifacts/screenshots/`。要刷新样例时显式指定输出目录：

```bash
python3 -m vulnguard demo --online --out artifacts/demo-run
```

看 rpm/apk 夹具和 Trivy 第二意见：

```bash
python3 -m vulnguard scan --source fixture --path demo/samples/rpm-apk --out artifacts/rpm-apk
python3 -m vulnguard scan --source fixture --path demo/lab --out artifacts/trivy-opinion
```

第二条会读 `demo/lab/trivy.json`（与 `demo/trivy/sample.json` 相同）。PATH 里有 `trivy` 时，还会再跑一次 `trivy fs`，两份结果去重后附在报告的「Trivy 第二意见」一节。没有 `trivy` 时这一节仍然有夹具内容。

已提交的两份报告：`artifacts/trivy-opinion/` 是没有 trivy 二进制时的结果；`artifacts/trivy-live/` 是本环境安装 Trivy 0.76.1 后、与夹具合并的结果。原始 JSON 在 `demo/trivy/live-fs.json`。`artifacts/rpm-apk/` 是 rpm/apk 夹具的离线报告。

## 测试

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q
```

## 用 Docker 扫一套旧服务

有 Docker 的机器可以：

```bash
docker compose up --build
```

Compose 拉起 `nginx:1.18.0`、`redis:5.0.7`、`mysql:5.7.44` 和一个只携带清单、不安装旧依赖的应用容器。VulnGuard 镜像里带有 Docker 客户端，并挂载宿主机的 `/var/run/docker.sock`。启动命令是 `--source docker`，只采集带 `vulnguard.scan=true` 标签的容器。容器日志里有一行 `巡检来源=docker`。界面在 http://127.0.0.1:8000 。

`/scan/lab` 仍挂在容器里，供 Trivy 夹具使用；资产清单本身来自正在运行的旧容器，而不是 `demo/lab` 的 dpkg 节选。`nginx:1.18.0` 镜像里有 Debian 包，扫描会读到那个包版本（本环境是 `1.18.0-2~buster`）并保留 `nginx/1.18.0` 横幅。Redis 官方镜像报告上游版本 `5.0.7`，不是 Debian 包，不会命中 CVE-2022-0543。要看这条 KEV，用 `demo/lab`。MySQL 镜像是 `5.7.44`，会命中 5.7 生命周期，而不会命中只影响 5.7.41 及更早版本的 CVE-2023-21980。

没有 Docker 守护进程时，不要用这条路径。`python3 -m vulnguard demo` 扫的是 `demo/lab`。

## 其他入口

```bash
python3 -m vulnguard scan --source local --path . --online
python3 -m vulnguard scan --source ssh --path 10.0.0.8 --ssh-user ubuntu
python3 -m vulnguard serve --interval-hours 24 --scan-on-start --online
python3 -m vulnguard approve plan-debian-redis-5-5-0-7-2-deb10u1 --approver 值班人甲 --comment "已核对回滚"
python3 -m vulnguard dry-run plan-debian-redis-5-5-0-7-2-deb10u1
python3 -m vulnguard refresh-feeds
```

定时也可以交给系统 cron，例如每天 02:00：

```bash
0 2 * * * cd /opt/vulnguard && python3 -m vulnguard scan --source fixture --path demo/lab --online --out runtime/reports/nightly
```

## 语言模型

不配置密钥时，方案说明由模板生成，命令仍然来自白名单，不来自模型。

```bash
export VULNGUARD_LLM_BASE_URL=https://api.openai.com/v1
export VULNGUARD_LLM_API_KEY=sk-...
export VULNGUARD_LLM_MODEL=gpt-4o-mini
```

`VULNGUARD_LLM_BASE_URL` 可以指向任何兼容 `/v1/chat/completions` 的服务。

真正执行白名单命令：

```bash
export VULNGUARD_ALLOW_APPLY=1
```

演示环境不要打开这个开关。

## 目录

| 路径 | 内容 |
| --- | --- |
| `vulnguard/` | 采集、匹配、优先级、方案、报告和 Web |
| `demo/lab/` | 可复现的演示资产 |
| `docs/设计文档.md` | 设计思路 |
| `ai-process/` | 任务原文、运行时提示词、技能文件、第三方仓库 |
| `artifacts/` | 样例报告和界面截图 |

设计细节、优先级公式和执行安全见 [docs/设计文档.md](docs/设计文档.md)。
