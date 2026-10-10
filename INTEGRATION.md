# 集成约定（A 编排 · 同进程整合 B）

**对外只开一个端口：http://127.0.0.1:8023**  
B 查询 API **默认嵌入主进程**（`TEAM_INTEL_MODE=embed`），**不需要**再起 `:8765`。

## 快速演示

| 项 | 地址 |
| --- | --- |
| **用户入口（唯一）** | **http://127.0.0.1:8023** |
| B 团队情报（同进程） | `http://127.0.0.1:8023/api/intelligence/*`、`GET /api/documents*` |

```bash
./scripts/demo-up.sh      # 默认单进程 embed
./scripts/demo-smoke.sh   # 整链只打 8023
```

- 若本机 Docker 可用：Compose 起 `b-seed` + `main-app`（共享 `intelligence.db` 卷）。
- 否则：本地 **一个** uvicorn（`main.py`），B 路由由 `EmbedBMiddleware` 派发。
- 遗留双进程：`TEAM_INTEL_MODE=sidecar DEMO_B_SIDECAR=1 ./scripts/demo-up.sh`（可选，非默认）。

## 浏览器验收

浏览器打开 **http://127.0.0.1:8023**：

1. 架构总览 → 整合条 B =「同进程嵌入」
2. 情报监测 →「立即刷新一轮」→ 应有 CVE + 文档
3. 团队情报健康：`http://127.0.0.1:8023/api/intelligence/health`

## 本机手动（单进程）

```bash
# 1) 准备演示库（只需一次）
intelligence/.venv/bin/python intelligence/seed_demo_db.py --force

# 2) 主应用（嵌入 B，无需 8765）
TEAM_INTEL_MODE=embed \
INTELLIGENCE_DB_PATH=intelligence/data/intelligence.db \
.venv/bin/python main.py
```

## 环境变量

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `TEAM_INTEL_MODE` | `embed` | `embed`=同进程；`sidecar`=遗留 HTTP :8765 |
| `INTELLIGENCE_DB_PATH` | `intelligence/data/intelligence.db` | B SQLite 路径 |
| `TEAM_INTEL_UPSTREAM` | `http://127.0.0.1:8765` | 仅 sidecar：A 直连 B |
| `TEAM_INTEL_PROXY` | sidecar 时 `1` | 仅 sidecar：8023 反代 B |
| `APP_HOST` / `APP_PORT` | `127.0.0.1` / `8023` | 主应用监听 |

## 冲突与整合说明

见 `/cursor/stores/self/docs/unify-resolve-conflicts.md`（根依赖 vs `intelligence/` lock、如何嵌入、sidecar 何时保留）。
