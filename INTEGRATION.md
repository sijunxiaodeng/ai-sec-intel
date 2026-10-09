# 三人整合约定（A 维护）

集成线只有 **`dev`**。`main` 仅在 A 确认可演示后晋升。  
详细操作见 store 文档（本仓库不复制长文）：团队整合手册 / 冒烟报告。

## 演示启动顺序（必须）

1. **B**（独立 venv，端口 **8765**）  
   - 离线演示库（无外网时）：

```bash
intelligence/.venv/bin/python intelligence/seed_demo_db.py --force
INTELLIGENCE_DB_PATH=intelligence/data/intelligence.db \
  intelligence/.venv/bin/python intelligence/run_intelligence_api_v6.py
```

   - 有真实采集时：先 `run_monitor.py --once`，再起 API（默认读 `intelligence/data/intelligence.db`）。

2. **主应用**（根目录 venv，端口 **8023**）

```bash
python -m rag.prepare   # 可选：历史样例
AUTO_INGEST_ON_COLLECT=1 python main.py
# 冒烟若不想联网抓关联资料：AUTO_INGEST_ON_COLLECT=0
```

3. 浏览器打开 `http://127.0.0.1:8023`，关键词如 `ollama`：监测 → 富化 → 问答。

## 环境变量

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `AUTO_INGEST_ON_COLLECT` | **`1`**（保持原行为） | 采集/富化后是否自动 `rag.ingest`；`0` 跳过 |
| `INTELLIGENCE_DB_PATH` | `intelligence/data/intelligence.db` | B API 只读库路径 |

## 文件冻结（所有权）

| 角色 | 可以改 | 禁止 |
| --- | --- | --- |
| **A** | `models.py`、`database/store.py`、`agents/orchestrator.py`、`agents/monitor_agent.py`、`agents/enrichment_agent.py`、`api/app.py`、`web/`、本文件 | — |
| **B** | `intelligence/**`、`collectors/` 来源（经 PR） | 直接推 `main`；改 `models` / 编排 |
| **C** | `enrichment/`、`rag/`、`questions/`、问答辅助实现 | **`agents/orchestrator.py`、`models.py`、`agents/monitor_agent.py`、`agents/enrichment_agent.py`**；直接推 `main` |

B/C 一律：`feature/*` → **PR → `dev`**。冲突找 A。不要 `git push --force` 到 `main`/`dev`。

## Agent 叙事（答辩用）

- **平台（A）**：Monitor / Enrichment / QA / Verifier + Orchestrator  
- **采集插件（B）**：独立服务 + `IntelligenceCollector` HTTP 适配  
- **富化与证据问答（C）**：`enrichment/` + `rag/`（及问答辅助模块）
