# VulnGuard 漏洞守卫

上海魔拾科技笔试成品。对照已经公开的漏洞清单，检查一套正在运行的系统，定期给出更新建议，并在人工确认后辅助走更新流程。界面、报告和设计文档都是中文。实现由 Cursor Cloud Agent 完成。

## 一分钟看懂

采集操作系统包、Nginx / Redis / MySQL，以及 Python、npm、Maven、Go 依赖，对照 OSV、策展公告、CISA KEV 和 EPSS 排序，写出可复核的更新方案。默认只预演。没有语言模型密钥时用固定模板，演示不依赖 API 密钥。

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m vulnguard demo --online
python3 -m vulnguard serve
```

浏览器打开 http://127.0.0.1:8000 。`demo` 和 `scan` 把报告写到 `runtime/reports/latest/`，该目录在 `.gitignore` 里，重复演示不会改动已提交文件。`--online` 访问 OSV、CISA KEV 和 FIRST EPSS；失败时改用 `vulnguard/data/` 里 2026-11-03 的快照，命令仍然成功。只想离线复现时去掉 `--online`。

已提交的在线样例是 [artifacts/demo-run/report.md](artifacts/demo-run/report.md)：主机 `moshi-lab-01`，资产 13，发现 29（严重 5、高危 12、中危 12、低危 0），更新方案 10。界面截图在 [artifacts/screenshots/](artifacts/screenshots/)。

数据库还是空的时候，单独运行 `python3 -m vulnguard serve` 也会先巡检一次。默认来源是 `auto`：先试 Docker，失败再用 `demo/lab`。先跑过上面的 `demo` 时，界面直接读已有记录。

## 交付物索引

| 面试官要看的 | 位置 |
| --- | --- |
| 设计思路与设计文档 | [docs/设计文档.md](docs/设计文档.md) |
| 开发任务原文（Prompt） | [ai-process/prompts/00-任务原文.md](ai-process/prompts/00-任务原文.md) |
| 运行时用户 Prompt | [ai-process/prompts/runtime-user.md](ai-process/prompts/runtime-user.md) |
| 运行时 Skill | [ai-process/skills/remediation-advisor.md](ai-process/skills/remediation-advisor.md) |
| 第三方开源仓库与数据源 | [ai-process/第三方开源仓库.md](ai-process/第三方开源仓库.md) |
| 开发记录与迭代取舍 | [ai-process/开发记录.md](ai-process/开发记录.md) |
| 在线样例报告 | [artifacts/demo-run/report.md](artifacts/demo-run/report.md)（同目录有 `report.html`、`findings.json`） |
| rpm/apk 夹具报告 | [artifacts/rpm-apk/report.md](artifacts/rpm-apk/report.md)：资产 6，发现 4，方案 4 |
| Trivy 第二意见，仅夹具 | [artifacts/trivy-opinion/report.md](artifacts/trivy-opinion/report.md) |
| Trivy 第二意见，夹具加本机 Trivy 0.76.1 | [artifacts/trivy-live/report.md](artifacts/trivy-live/report.md)，原始 JSON 在 `demo/trivy/live-fs.json` |
| 界面截图 | [总览](artifacts/screenshots/01-dashboard.png)、[Log4Shell](artifacts/screenshots/02-log4shell.png)、[Redis 方案](artifacts/screenshots/03-redis-plan.png)、[资产](artifacts/screenshots/04-assets.png) |
| 公开数据快照 | `vulnguard/data/` |
| 可复现资产 | `demo/lab/`、`demo/samples/rpm-apk/`、`demo/trivy/sample.json` |

## 它做什么

1. 采集资产。本机读取 dpkg，以及存在时的 rpm、apk，再读中间件横幅和目录里的 `requirements.txt`、`package.json`、`pom.xml`、`go.mod`。Docker 读取容器里的 nginx、Redis、MySQL，以及 `/opt/app` 下的这四种清单；发行版包只留这三个中间件。SSH 只读远端的 dpkg、rpm、apk 和中间件横幅。
2. 对照公开数据：OSV.dev、随包策展公告、CISA KEV、EPSS。网络不可用时使用 2026-11-03 的快照。
3. 排出优先级：CVSS、是否在 KEV、EPSS、暴露面，并写出计算过程。
4. 生成更新方案：变更前检查、步骤、回滚和验证。说明可以由兼容 OpenAI 的接口生成；没有密钥时使用固定模板。
5. 默认只预演。批准后，只有白名单里的命令才可能执行，并且还要打开 `VULNGUARD_ALLOW_APPLY=1`。

## 已知局限

- 操作系统清单以 Debian/dpkg 为主。rpm 与 apk 已能只读采集；匹配仍把 nginx、Redis、MySQL 当作中间件，其余系统包不逐包请求 OSV。
- Trivy 的 JSON 只作为第二意见附在报告里，不替换 OSV 主路径。Grype、Syft、osv-scanner 仍只检测是否安装，不解析输出。
- SSH 不读取应用清单。应用清单来自本机目录，或容器内的 `/opt/app`。
- 默认可复现路径是 `demo/lab`。`docker compose` 需要本机有 Docker；官方 Redis 镜像不会套用 Debian 特有的 CVE-2022-0543。
- Web 界面没有登录和鉴权，只适合本机演示。

## 样例报告怎么刷新

要覆盖已提交样例时，显式指定输出目录：

```bash
python3 -m vulnguard demo --online --out artifacts/demo-run
python3 -m vulnguard scan --source fixture --path demo/samples/rpm-apk --out artifacts/rpm-apk
python3 -m vulnguard scan --source fixture --path demo/lab --out artifacts/trivy-opinion
```

第三条会读 `demo/lab/trivy.json`（与 `demo/trivy/sample.json` 相同）。PATH 里有 `trivy` 时，还会再跑一次 `trivy fs --scanners vuln --format json --quiet`，两份结果按「编号 + 包名 + 已安装版本」去重后附在「Trivy 第二意见」。没有 `trivy` 时这一节仍然有夹具内容。`artifacts/trivy-opinion/` 是没有 trivy 二进制时的结果；`artifacts/trivy-live/` 是本环境安装 Trivy 0.76.1 后、与夹具合并的结果。

## 测试

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q
```

当前为 31 个测试。覆盖版本比较、CVSS、优先级、清单解析、Docker/SSH 输出、离线匹配、白名单与未批准拒绝、重复 CVE 合并、rpm/apk 解析，以及 Trivy JSON 与 OSV 主路径的对照。

## 用 Docker 扫一套旧服务

有 Docker 的机器可以：

```bash
docker compose up --build
```

Compose 拉起 `nginx:1.18.0`、`redis:5.0.7`、`mysql:5.7.44` 和一个只携带清单、不安装旧依赖的应用容器。VulnGuard 镜像里带有 Docker 客户端，并挂载宿主机的 `/var/run/docker.sock`。环境变量 `VULNGUARD_DOCKER_PS_FILTER=label=vulnguard.scan=true`，启动参数是 `--source docker`，因此只采集带这个标签的容器。不设置该变量时，`scan --source docker` 会列出全部正在运行的容器。容器日志里有一行 `巡检来源=docker`。界面在 http://127.0.0.1:8000 。

`/scan/lab` 仍挂在容器里，供 Trivy 夹具使用；资产清单本身来自正在运行的旧容器，而不是 `demo/lab` 的 dpkg 节选。`nginx:1.18.0` 镜像里有 Debian 包，扫描会读到那个包版本（本环境是 `1.18.0-2~buster`）并保留 `nginx/1.18.0` 横幅。Redis 官方镜像报告上游版本 `5.0.7`，不是 Debian 包，不会命中 CVE-2022-0543。要看这条 KEV，用 `demo/lab`。MySQL 镜像是 `5.7.44`，会命中 5.7 生命周期，而不会命中只影响 5.7.41 及更早版本的 CVE-2023-21980。

客户端连不上守护进程时这次巡检失败，不会改去扫 `/scan/lab`。没有 Docker 时，用 `python3 -m vulnguard demo`，它扫的是 `demo/lab`。

## 其他入口

```bash
python3 -m vulnguard scan --source local --path . --online
python3 -m vulnguard scan --source ssh --path 10.0.0.8 --ssh-user ubuntu
python3 -m vulnguard serve --interval-hours 24 --scan-on-start --online
python3 -m vulnguard approve plan-debian-redis-5-5-0-7-2-deb10u1 --approver 值班人甲 --comment "已核对回滚"
python3 -m vulnguard dry-run plan-debian-redis-5-5-0-7-2-deb10u1
python3 -m vulnguard refresh-feeds
```

`serve --interval-hours 24` 启动时若带 `--scan-on-start`，报告写到 `runtime/reports/latest/`；之后的定时巡检写到 `runtime/reports/scheduled/`，每次覆盖该目录。界面上的发现来自数据库。`/report.html` 优先打开 `runtime/reports/latest/`，没有这份文件时才回退到 `artifacts/demo-run/`。

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

设计细节、优先级公式和执行安全见 [docs/设计文档.md](docs/设计文档.md)。
