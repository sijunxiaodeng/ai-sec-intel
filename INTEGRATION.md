# 集成约定（A 编排 · 同进程统一 B）

**对外只开一个端口：http://127.0.0.1:8023**

**一个 venv（根 `.venv`）** 跑 A + 嵌入的 B 查询与多源监测。
默认 `TEAM_INTEL_MODE=embed`，**不需要** `:8765`。

## 快速演示

```bash
git pull origin main
python -m pip install -r requirements.txt
python scripts/offline_demo.py  # 首次自动生成合成数据，不联网采集
# 或 ./scripts/demo-up.sh（默认离线；首次安装/构建需包网络）
```

浏览器只打开 **http://127.0.0.1:8023**：

1. 架构总览 → B =「同进程嵌入」
2. 离线演示已有 4 条合成漏洞和 4 份资料；查看情报、资料和证据问答
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

根 requirements.txt 引用 intelligence/requirements.lock.txt，A/B/C 共用 FastAPI 0.143、Pydantic 2.14 和同一 HTTP 库版本。主应用的校验模型已迁移到 Pydantic v2；不再混用两套互斥约束。生产进程仍可分开部署，这是职责和故障隔离，不是为了回避依赖冲突。

真实数据采集统一使用 `python intelligence/run_monitor.py` 或 GitHub Actions。A 只消费 B 的完整变更流。NVD/OSV 的根目录直采已移除，OSV 已移入 B，全文抓取仍由富化阶段完成。

`DEMO_NETWORK=online ./scripts/demo-up.sh` 显式进入原联网演示；正式数据使用 docs/正式数据部署与交付.md 的两个配置之一。
