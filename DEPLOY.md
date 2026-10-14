# 部署与一键启动

产品面只有一个入口：**http://127.0.0.1:8023**（知识库 / 情报监测 / 富集 / 问答都在这一端口）。

## 依赖

- Docker Engine + `docker compose` 插件
- 首次构建镜像需能访问包源；**默认离线演示**跑起来后不再访问公网采集或模型

复制正式环境变量模板（仅正式部署需要）：`.env.production.example` → `.env.production`（勿提交）。

## 一键启动（推荐：离线演示）

```bash
docker compose -f docker-compose.offline.yml up --build -d
```

浏览器打开 **http://127.0.0.1:8023**。健康检查：`curl -sf http://127.0.0.1:8023/api/overview`。

停止（保留数据卷）：

```bash
docker compose -f docker-compose.offline.yml down
```

也可：`./scripts/demo-up.sh`（有 Docker 时走上述 offline compose；无 Docker 时回退本机 `scripts/offline_demo.py`）。停止：`./scripts/demo-down.sh`。冒烟：`./scripts/demo-smoke.sh`。

## Compose 文件怎么选

| 文件 | 用途 | 对外端口 | 数据落盘 |
| --- | --- | --- | --- |
| `docker-compose.offline.yml` | **默认演示**（合成样例，不联网采集） | `127.0.0.1:8023` | 卷 `offline-demo-data` → 容器内 `/app/data` |
| `docker-compose.yml` | 联网演示 / 联调（embed；种子写演示卷） | `127.0.0.1:8023` | 卷 `b-data`、`main-data` |
| `docker-compose.production.yml` | 正式：常驻采集机 | `:8023`（产品） | `b-production-data`、`main-production-data` |
| `docker-compose.actions.yml` | 正式：消费 Actions 快照 | `:8023`（产品） | `b-actions-mirror-data`、`main-actions-data` |

联网演示：

```bash
DEMO_NETWORK=online ./scripts/demo-up.sh
# 或
docker compose -f docker-compose.yml up --build -d
```

项目名默认见各 compose 的 `name:`（离线为 `ai-sec-intel-offline-demo`）。

## 正式数据（进阶）

Windows Docker Desktop 的正式 Actions 拉取部署入口是 `scripts/production-up.ps1 -Sync`，包括引擎/端口/配置检查和真实快照、漏洞/资料两路持久游标验收。具体操作见 [Windows 部署与闭环验收](docs/Docker%20Desktop部署闭环.md)；此模式需要在本机配置仓库 Actions 只读令牌，无需本机 Python。

与演示卷分开，**不要与演示 compose 同时起**。详见 [正式数据部署与交付](docs/正式数据部署与交付.md)。

```bash
bash scripts/production-up.sh actions      # 或 collector
docker compose -f docker-compose.actions.yml down   # 对应文件停止
```

对外仍只开 **:8023** 产品面；内部查询进程端口不是产品入口。

## 不要做的事

- 不要同时启动演示 compose 与正式 production/actions
- 不要对业务数据执行 `docker compose down --volumes`
- 不要把密钥写进仓库
