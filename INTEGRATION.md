# 三人整合约定（A 维护）

集成线只有 **`dev`**。`main` 仅在 A 确认可演示后晋升。

## 一键统一演示环境（推荐）

**对外只开一个端口：http://127.0.0.1:8023**  
B 仍在本机 `127.0.0.1:8765` 跑（反代后端），**浏览器不要打开 8765**。

| 角色 | 地址 |
| --- | --- |
| **用户入口（唯一）** | **http://127.0.0.1:8023** |
| B 团队情报（经反代） | `http://127.0.0.1:8023/api/intelligence/*`、`GET /api/documents*` |
| B 上游进程（仅本机） | `127.0.0.1:8765`（`TEAM_INTEL_UPSTREAM`） |

```bash
./scripts/demo-up.sh      # 或 make demo-up（含 demo-collect：B 多源尝试 + C team-sync）
./scripts/demo-smoke.sh   # 或 make demo-smoke（整链只打 8023）
./scripts/demo-collect.sh # 单独再跑多源/资料库同步
./scripts/demo-down.sh    # 停止
```

- 优先使用根目录 **`docker-compose.yml`**（`b-api` + `main-app`，healthcheck + `restart: unless-stopped`）。
- 若本机 Docker 守护进程不可用，脚本自动回退到**本地双进程**（8765 仅本机 + 8023 对外反代）。
- `demo-up` 会调用 `demo-collect`：有网时尝试 B `run_monitor --once`（超时则保留多 CVE 合成种子）；并 `POST /api/library/team-sync`。
- 演示默认 `AUTO_INGEST_ON_COLLECT=0`（避免每次监测长时间抓网页）；需要时：

```bash
AUTO_INGEST_ON_COLLECT=1 ./scripts/demo-up.sh
```

连续运行：

- Compose：`docker compose -p ai-sec-intel-demo logs -f`；容器 `restart: unless-stopped`。
- 本地模式：日志在 `.demo/b-api.log`、`.demo/main-api.log`；进程挂了需重新 `./scripts/demo-up.sh`。

浏览器打开 **http://127.0.0.1:8023**（唯一入口）：

1. **自动监测** → 打开即应有自动情报流；可选「立即刷新一轮」
2. **资料库沉淀** → 查阅已沉淀资料
3. **情报富集** → 选 CVE 补 EPSS/KEV，并评估影响资产
4. **证据问答** → 演示 CVE：`CVE-2099-90001` 等  
团队情报健康：`http://127.0.0.1:8023/api/intelligence/health`

详见：`/cursor/stores/self/docs/single-port-integrate.md`

## 手动启动（不用一键脚本时）

1. **B 上游**（独立 venv，**只绑本机 8765**）

```bash
intelligence/.venv/bin/python intelligence/seed_demo_db.py --force
INTELLIGENCE_DB_PATH=intelligence/data/intelligence.db \
  intelligence/.venv/bin/python intelligence/run_intelligence_api_v6.py --host 127.0.0.1 --port 8765
```

2. **主应用**（根目录 venv，端口 **8023**，反代 B）

```bash
TEAM_INTEL_UPSTREAM=http://127.0.0.1:8765 \
TEAM_INTEL_BASE_URL=http://127.0.0.1:8765 \
TEAM_INTEL_PROXY=1 \
AUTO_INGEST_ON_COLLECT=0 \
python main.py
```

Compose 内主应用：`TEAM_INTEL_UPSTREAM=http://b-api:8765`，用户仍只访问映射的 8023。

## 环境变量

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `AUTO_INGEST_ON_COLLECT` | 演示脚本 **`0`**；代码默认仍为 `1` | 采集/富化后是否自动抓关联资料 |
| `TEAM_INTEL_UPSTREAM` | `http://127.0.0.1:8765` | A 服务端直连 B（勿指回 8023，防单 worker 死锁） |
| `TEAM_INTEL_BASE_URL` | 同 UPSTREAM | 兼容旧名；采集器用 UPSTREAM 优先 |
| `TEAM_INTEL_PROXY` | `1` | 在 8023 上反代 `/api/intelligence/*` 与 GET `/api/documents*` |
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
| A | `api/`、`web/`、`agents/orchestrator.py`、根目录脚本与 INTEGRATION | 擅自改 B `intelligence/` 采集语义 |
| B | `intelligence/` | 改 A Web/编排默认路径 |
| C | `enrichment/`、`rag/`（约定范围内） | 改 B API 契约而不通知 |

为何不能把 B 嵌进同一 Python 进程：A 为 FastAPI 0.95 / Pydantic v1，B 为新版 FastAPI / Pydantic v2——依赖冲突，故用 **反代** 而不是 mount 子应用。
