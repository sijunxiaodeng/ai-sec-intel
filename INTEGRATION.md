# 三人整合约定（A 维护）

集成线只有 **`dev`**。`main` 仅在 A 确认可演示后晋升。

## 一键统一演示环境（推荐）

固定端口（不要改）：

| 服务 | 地址 |
| --- | --- |
| 主应用 UI / API | **http://127.0.0.1:8023** |
| B 情报 API | **http://127.0.0.1:8765** |

```bash
./scripts/demo-up.sh      # 或 make demo-up（含 demo-collect：B 多源尝试 + C team-sync）
./scripts/demo-smoke.sh   # 或 make demo-smoke
./scripts/demo-collect.sh # 单独再跑多源/资料库同步
./scripts/demo-down.sh    # 停止
```

- 优先使用根目录 **`docker-compose.yml`**（`b-api` + `main-app`，healthcheck + `restart: unless-stopped`）。
- 若本机 Docker 守护进程不可用，脚本自动回退到**本地双进程**（同样绑定 8765 / 8023）。
- `demo-up` 会调用 `demo-collect`：有网时尝试 B `run_monitor --once`（超时则保留多 CVE 合成种子）；并 `POST /api/library/team-sync`。
- 演示默认 `AUTO_INGEST_ON_COLLECT=0`（避免每次监测长时间抓网页）；需要时：

```bash
AUTO_INGEST_ON_COLLECT=1 ./scripts/demo-up.sh
```

连续运行：

- Compose：`docker compose -p ai-sec-intel-demo logs -f`；容器 `restart: unless-stopped`。
- 本地模式：日志在 `.demo/b-api.log`、`.demo/main-api.log`；进程挂了需重新 `./scripts/demo-up.sh`。

浏览器打开 http://127.0.0.1:8023 ，默认关键词 `llm,...`（AI 安全集合）：监测 → 富化 → 问答（演示 CVE：`CVE-2099-90001` 等合成多源）。

## 手动启动（不用一键脚本时）

1. **B**（独立 venv，端口 **8765**）

```bash
intelligence/.venv/bin/python intelligence/seed_demo_db.py --force
INTELLIGENCE_DB_PATH=intelligence/data/intelligence.db \
  intelligence/.venv/bin/python intelligence/run_intelligence_api_v6.py
```

2. **主应用**（根目录 venv，端口 **8023**）

```bash
TEAM_INTEL_BASE_URL=http://127.0.0.1:8765 \
AUTO_INGEST_ON_COLLECT=0 \
python main.py
```

Compose 内主应用通过 `TEAM_INTEL_BASE_URL=http://b-api:8765` 访问 B。

## 环境变量

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `AUTO_INGEST_ON_COLLECT` | 演示脚本 **`0`**；代码默认仍为 `1` | 采集/富化后是否自动抓关联资料 |
| `TEAM_INTEL_BASE_URL` | `http://127.0.0.1:8765` | 主应用访问 B 的基址（compose 内为 `http://b-api:8765`） |
| `INTELLIGENCE_DB_PATH` | `intelligence/data/intelligence.db` | B API 只读库路径 |
| `APP_HOST` / `APP_PORT` | `127.0.0.1` / `8023` | 主应用监听（容器内 `0.0.0.0`） |
| `DEMO_MODE` | `auto` | `compose` / `local` / `auto` |
| `DEMO_FORCE_SEED` | `0` | 本地模式强制重建演示库 |
| `DEMO_KEYWORD` | `llm` | 冒烟主关键词 |
| `DEMO_B_MONITOR` | `1` | demo-collect 是否尝试 B 真采（超时保留种子） |
| `DEMO_MONITOR_TIMEOUT` | `180` | B `run_monitor` 整轮超时秒数 |
| `AI_SECURITY_KEYWORDS` | llm,vllm,… | 冒烟广度检查用关键词表 |

## 文件冻结（所有权）

| 角色 | 可以改 | 禁止 |
| --- | --- | --- |
| **A** | `models.py`、`database/store.py`、`agents/orchestrator.py`、`agents/monitor_agent.py`、`agents/enrichment_agent.py`、`api/app.py`、`web/`、`docker-compose.yml`、`scripts/demo-*.sh`、本文件 | — |
| **B** | `intelligence/**`、`collectors/` 来源（经 PR） | 直接推 `main`；改 `models` / 编排 |
| **C** | `enrichment/`、`rag/`、`questions/`、问答辅助实现 | **`agents/orchestrator.py`、`models.py`、`agents/monitor_agent.py`、`agents/enrichment_agent.py`**；直接推 `main` |

B/C 一律：`feature/*` → **PR → `dev`**。不要 `git push --force` 到 `main`/`dev`。

## Agent 叙事（答辩用）

- **平台（A）**：Monitor / Enrichment / QA / Verifier + Orchestrator  
- **采集插件（B）**：独立服务 + `IntelligenceCollector` HTTP 适配  
- **富化与证据问答（C）**：`enrichment/` + `rag/`（及问答辅助模块）
