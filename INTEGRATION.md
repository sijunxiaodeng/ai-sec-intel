# 系统集成与部署约定

**对外只开一个端口：http://127.0.0.1:8023**

默认 `TEAM_INTEL_MODE=embed`：B 查询接口嵌入主应用；B 多源采集在独立 Python 子进程运行，避免同名模块导入冲突。采集超时终止该进程树，已提交的 SQLite 数据保留。此模式不需启动 `8765`。

根 `requirements.txt` 引用 `intelligence/requirements.lock.txt`，A/B/C 共用同一核心依赖版本。正式数据与交付见 [正式数据部署与交付](docs/正式数据部署与交付.md)。

## Bash 一键演示

运维前门是根目录 **Makefile**（说明见 [DEPLOY.md](DEPLOY.md)）：

```bash
git pull origin main
make up            # 默认离线；有 Docker → offline compose，否则本地 .venv
make smoke
make down
```

等价脚本：`./scripts/demo-up.sh` / `demo-smoke.sh` / `demo-down.sh`。无 Docker 时先 `python -m pip install -r requirements.txt`；也可直接 `python scripts/offline_demo.py`（前台）。默认离线合成样例；联网演示用 `make online` 或 `DEMO_NETWORK=online`。

只启动离线容器、不触发联网采集时：

```bash
AUTO_MONITOR_ENABLED=0 B_MONITOR_ENABLED=0 AUTO_INGEST_ON_COLLECT=0 docker compose up -d --build --wait
```

首次启动可生成标注为合成的演示库；以后重复启动 `b-seed` 保留已有数据库。`--force` / `DEMO_FORCE_SEED=1` 会重建演示库，仅用于明确需要重置的可丢弃环境。合成卡片与历史回填不能作为实时监测、准确率或真实资产证据。

## Windows PowerShell 本地启动

在仓库根目录执行，使用 Python 3.12：

```powershell
$env:PYTHONUTF8='1'
$env:PYTHONIOENCODING='utf-8'
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements-test.txt
.venv/Scripts/python.exe intelligence/seed_demo_db.py
.venv/Scripts/python.exe -m rag.prepare
.venv/Scripts/python.exe main.py
```

`rag.prepare` 加载历史证据，不准备语义模型。后台默认启动后一轮采集，之后每轮完成再等待 15 分钟；离线演示须在启动前设置 `$env:AUTO_MONITOR_ENABLED='0'` 和 `$env:B_MONITOR_ENABLED='0'`。前者关闭整条后台计划任务；`AUTO_MONITOR_ON_START=0` 仅跳过启动轮。真实采集恢复为 `1`，网页点击“立即刷新一轮”，检查各来源结果。

旧 HTTP 模式须显式设置 `TEAM_INTEL_MODE=sidecar`、本机 upstream，并用第二个虚拟环境启动 B；旧模式操作见 [部署与联调](验收包/部署与联调.md)。

## 环境变量及数据口径

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `TEAM_INTEL_MODE` | `embed` | B 查询嵌入；`sidecar` 为旧本机 HTTP 模式 |
| `INTELLIGENCE_DB_PATH` | `intelligence/data/intelligence.db` | B SQLite 路径；Compose 使用挂载路径 |
| `APP_SETTINGS_PATH` | 本地 `config/local.json`；容器 `/app/data/model-settings.json` | 模型设置原子保存；容器使用持久数据卷，重建后保留 |
| `B_MONITOR_ENABLED` / `B_MONITOR_ON_REFRESH` | `1` / `1` | 启用 B 子进程采集、主监测前刷新；离线/镜像可关闭 |
| `AUTO_MONITOR_ON_START` | `1` | 后台启动后一轮采集 |
| `AUTO_MONITOR_ENABLED` | `1` | 后台自动调度总开关；关闭后仍可显式手动调用联网采集 |
| `MONITOR_INTERVAL_MINUTES` | `15` | 完成一轮后的等待分钟数；显式设置优先 |
| `MONITOR_INTERVAL_HOURS` | 未设置 | 兼容旧小时设置；分钟设置为空时生效 |
| `B_MONITOR_SOURCE_TIMEOUT` | `45` | 单来源秒数 |
| `B_MONITOR_OVERALL_TIMEOUT` | `180` | 子进程工作截止秒数，另有有界进程清理耗时 |
| `AUTO_INGEST_ON_COLLECT` | 主应用 `1`，演示/Compose `0` | 每轮自动抓取 CVE 关联全文；独立资料同步仍由对应请求/计划任务执行 |
| `ROOT_NVD_ENABLED` | 未设置 | 默认 embed/sidecar 使用监测模块 NVD；设 `1` 显式启用根兼容采集器 |

轮询间隔不等于发布到采集延迟。总览优先展示监测实测来源类别及有效实时样本，包括真实零值；没有监测统计才展示资料存档类别/根兼容样本并标明口径。来源名数和 URL 数不能换算为类别数。日期无精确时间、未来时间、历史/合成回填不计合格时效样本。

根 OSV 增量按包保存“已实际入库的条目及内容版本”，限额后剩余条目下轮继续；旧全局游标重放以恢复可能遗漏的资料。根 NVD 验证完整分页及写库成功后才推进关键词时间窗；超出分页预算记录失败、不跳过窗口，可能需收窄查询或增加预算，不能声称任意历史规模已完整补采。

采集状态区分 `success`、`partial`、`failed`。全部实际来源失败不推进游标、不覆盖知识库；成功的空轮正常结束。旧缓存读取成功不代表本轮采集成功。EPSS/KEV 最近失败时保留并标明上次成功值，同时展示最新查询失败及时间。

真实数据采集统一使用 `python intelligence/run_monitor.py` 或 GitHub Actions。主应用消费监测变更流。`DEMO_NETWORK=online ./scripts/demo-up.sh` 显式进入联网演示。

## 已有 Docker 数据卷升级

旧主容器使用 UID 10002，新主容器与监测统一 UID/GID 10001。旧 `main-data` 卷可能需迁移所有者；rebuild 不会改已有卷权限。先停止应用和独立采集写入并备份，再操作。旧容器若已保存模型设置，还需在重建前从 `/app/config/local.json` 单独备份，迁入新数据卷的 `/app/data/model-settings.json`；卷备份不包含旧容器的 config 目录。**不使用 `docker compose down --volumes` 修复业务数据。**

以下为 Bash 命令。备份只读打包两处挂载，保留在自己的环境：

```bash
docker compose stop main-app
docker compose --profile sidecar stop b-api
mkdir -p backups
docker compose run --rm --no-deps --user 0 main-app tar -C /app -czf - data intelligence/data > backups/state-before-owner-migration.tar.gz
```

若旧容器已保存模型设置，继续执行以下备份；复制的是本机配置文件，不显示其内容。没有保存过设置时跳过这一组：

```bash
mkdir -p backups
test ! -e backups/legacy-model-settings.json
docker compose cp main-app:/app/config/local.json backups/legacy-model-settings.json
```

备份完成后构建新镜像：

```bash
docker compose build main-app b-seed
```

已备份旧模型配置时，在新镜像 build 完成、应用仍停止时执行下面一组，将备份迁入持久卷；没有旧配置则跳过。新路径已有配置会中止，须先核对保留哪份。之后再执行所有者迁移和启动：

```bash
docker compose run --rm --no-deps --user 0 -v "$(pwd)/backups:/backup:ro" main-app python -c "import os; from pathlib import Path; s=Path('/backup/legacy-model-settings.json'); d=Path('/app/data/model-settings.json'); assert not d.exists(), 'destination settings already exist'; d.write_bytes(s.read_bytes()); os.chown(d,10001,10001); os.chmod(d,0o600)"
```

`backups/` 已从 Git 与 Docker 构建排除；包含密钥的备份不提交仓库。Windows 本地仍使用原 `config/local.json`，不需此迁移。

所有升级环境最后检查并迁移卷所有者，再启动：

```bash
docker compose run --rm --no-deps --user 0 main-app python scripts/migrate_volume_owner.py
docker compose run --rm --no-deps --user 0 main-app python scripts/migrate_volume_owner.py --apply
docker compose up -d --wait
```

迁移默认只检查；`--apply` 仅把 `/app/data` 和 `/app/intelligence/data` 中 UID 10002 的普通文件/目录改为 10001，不删除或改内容。符号链接、特殊文件或其他所有者会中止，须人工核对。不要用 Windows PowerShell 5 的文本重定向执行二进制备份命令，可使用 Bash 或 Docker 文件复制备份。

本机没有 Docker，不能据本地单元测试宣布容器部署通过。新增 CI 在 Linux 构建整个 Compose、核对旧卷迁移、跨服务写库、重复 seed 后保留数据以及重建主容器后的模型设置持久化；实际结果以对应提交的 Actions 为准。CI 使用虚构 Key，不向模型服务请求。

## 问答与验收边界

资料问答默认为原文摘录；“通用跨文档推理”模式显式启用模型，执行有界问题分解、资料检索、结论生成和引用复核。推断须至少引用两份不同资料，保存条件、缺失前提及来源版本。具体 CVE 仍走漏洞问答；模型不可用或证据失效时回退原文，不执行资料中的命令。

模型阶段共享 5 秒软预算，不代表整个 HTTP 请求已达到比赛 5 秒要求。跨文档语义正确率、独立富化标签、真实发布到采集延迟、PoC 运行结果和真实资产定位需另行验收。当前记录见 [系统整改与回归](验收包/系统整改与回归.md)。
