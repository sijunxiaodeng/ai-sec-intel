# 集成约定（A 编排 · 同进程统一 B）

**对外只开一个端口：http://127.0.0.1:8023**  
**一个 venv（根 `.venv`）** 跑 A + 嵌入的 B 查询与多源监测。  
默认 `TEAM_INTEL_MODE=embed`，**不需要** `:8765`。

## 快速演示

```bash
git pull origin main
./scripts/demo-up.sh      # 单进程 embed
./scripts/demo-smoke.sh   # 整链只打 8023
```

浏览器只打开 **http://127.0.0.1:8023**：

1. 架构总览 → B =「同进程嵌入」
2. 情报监测 →「立即刷新一轮」（会先跑 B 多源，再读库）
3. `POST /api/monitor/b-cycle` / `GET /api/intelligence/health`

## 环境变量

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `TEAM_INTEL_MODE` | `embed` | 同进程；`sidecar` 遗留 HTTP |
| `INTELLIGENCE_DB_PATH` | `intelligence/data/intelligence.db` | B SQLite |
| `B_MONITOR_ON_REFRESH` | `1` | monitor/run 与定时先刷 B |
| `B_MONITOR_SOURCE_TIMEOUT` | `45` | 单源超时（秒） |
| `B_MONITOR_OVERALL_TIMEOUT` | `180` | 整轮墙钟（秒） |

## 依赖

见 `/cursor/stores/self/docs/unify-resolve-conflicts.md`：根 pin 保留 FastAPI 0.95 / Pydantic v1；另装 `requests` + `python-dotenv` 供 B 监测。
