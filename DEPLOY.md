# 部署与一键启动

产品面只有一个入口：**http://127.0.0.1:8023**（知识库 / 情报监测 / 富集 / 问答都在这一端口）。

## 依赖

- Docker + `docker compose`（推荐），或本机 Python 3.12+
- 首次装依赖 / 构建镜像需要能访问包源；**默认离线演示**跑起来后不再访问公网采集或模型

```bash
# 无 Docker 时先装依赖
python3 -m pip install -r requirements.txt
```

## 一键启动

根目录 Makefile 是前门：

| 命令 | 作用 |
| --- | --- |
| `make up` | 启动（**默认离线演示**） |
| `make down` | 停止 |
| `make demo` | 启动 + 冒烟 |
| `make offline` | 显式离线（同默认） |
| `make online` | 联网演示 |
| `make smoke` | 冒烟 |
| `make status` | 探测 :8023 |
| `make logs` | 跟随日志 |

等价脚本：`./scripts/demo-up.sh` / `demo-down.sh` / `demo-smoke.sh`。

浏览器打开 **http://127.0.0.1:8023**。

## 实际走哪条路径

| 条件 | 路径 | 数据落盘 |
| --- | --- | --- |
| `make up` + 有 Docker | `docker-compose.offline.yml` | Docker 卷 `offline-demo-data` |
| `make up` + 无 Docker | `scripts/offline_demo.py` | `.demo/offline/` |
| `make online` + Docker | `docker-compose.yml`（embed，种子写演示卷） | 卷 `b-data`、`main-data` |
| `make online` + 无 Docker | 本地 embed（`.venv`） | `.demo/b-data/`、`.demo/main-data/` |

Compose 项目名默认 `ai-sec-intel-demo`（离线为 `ai-sec-intel-demo-offline`）。可用环境变量 `COMPOSE_PROJECT` 覆盖。

## 停止

```bash
make down
```

只停本仓库演示脚本记下的进程 / 对应 compose 项目，不会删 Docker 卷。正式数据卷与演示卷分开。

## 正式数据（进阶）

演示与正式写入端分开，**不要与 `make up` 同时起**。详见 [正式数据部署与交付](docs/正式数据部署与交付.md)。

```bash
make prod-actions      # GitHub Actions 快照消费
make prod-collector    # 常驻采集机
make prod-down         # 停止正式 compose
```

对外仍只开 **:8023** 产品面；内部查询进程端口不作为产品入口。

## 不要做的事

- 不要同时启动演示 compose 与正式 production/actions
- 不要对业务数据执行 `docker compose down --volumes`
- 不要把密钥写进仓库；正式环境用本地 `.env.production`（见 `.env.production.example`）
