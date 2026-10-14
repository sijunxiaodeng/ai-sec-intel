# Windows Docker Desktop 部署与闭环验收

这里部署真实 GitHub Actions 情报：云端采集 → 本机拉取可信快照 → B API → 漏洞与资料两路持久入库。正式模式不生成演示样例，不需要本机 Python，也不要求公网服务器或开通 Actions 推送。

## 1. 准备 Docker 和代码

打开 Docker Desktop，等待 **Engine running**，并使用 **Linux containers**。在新的 PowerShell 窗口运行：

```powershell
docker info --format '{{.OSType}}'
docker compose version
```

第一条应输出 `linux`。如果无法连接 Docker，继续等待 Engine 启动；按照 Docker Desktop 提示完成 WSL 2 安装或重启。不要先执行项目部署。

代码可从 [GitHub main 分支](https://github.com/sijunxiaodeng/ai-sec-intel)点击 **Code → Download ZIP**，解压到本机目录；有 Git 也可 `git clone https://github.com/sijunxiaodeng/ai-sec-intel.git`。打开包含 `docker-compose.actions.yml` 的目录，在地址栏输入 `powershell` 回车。代码需包含 `scripts/production-up.ps1` 和 `scripts/deployment_check.py`；旧压缩包应重新下载。

## 2. 在本机配置读取凭据

```powershell
if (!(Test-Path .env.production)) { Copy-Item .env.production.example .env.production }
notepad .env.production
```

只在本机填写 `GITHUB_TOKEN=`。在 GitHub **Settings → Developer settings → Personal access tokens → Fine-grained tokens** 新建读取令牌，选择 `sijunxiaodeng/ai-sec-intel` 仓库，授予 **Actions: Read-only** 和默认 **Metadata: Read-only**，设置合理有效期。该令牌用于下载 Actions 产物，不需要代码写权限。组织仓库如需审批，应先等待仓库授权。

保存并关闭记事本。令牌不要发到聊天、截图或命令行；不要提交 `.env.production`。该文件已被 Git 和 Docker 构建排除。`ACTIONS_INGEST_TOKEN` 可以留空，本机使用自动拉取，不需要公网推送。此流程不会配置或调用付费模型。

## 3. 启动并核对真实闭环

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\production-up.ps1 -Sync
```

`ExecutionPolicy Bypass` 仅对这次 PowerShell 进程生效。脚本检查 Linux Engine、配置、另一正式采集项目和本机端口，再构建并启动服务。首次构建需下载 Python 基础镜像与依赖；请保持网络连接。

脚本随后从容器内读取 GitHub 的真实最新采集运行编号和完整代码 SHA，等待部署提供该代际。`-Sync` 显式触发已有漏洞与资料变更的本机导入，核对两路已提交的游标都追到该快照的上限。它不会重跑云采集、导入演示样例或发起模型调用。

验收 JSON 中必须满足 `deployment_import_loop_verified=true`：指定真实快照已提供、漏洞和资料持久游标均已追平、自动镜像轮询状态正常。报告也分别显示 `snapshot_serving_verified` 与 `consumption_verified`；实际字段、代际切换及失败原因以输出为准。单独 HTTP 200、容器启动或页面能打开，都不算闭环完成。富化和索引处理另有队列，`processing_verified=false` 保留其独立验收边界。报告同时保存在主应用数据卷的 `deployment-proof.json` 中。

成功后打开 **http://127.0.0.1:8023**。如第一次下载较慢，保留服务运行，稍后重试：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\production-check.ps1 -Sync -WaitSeconds 900
```

省略 `-Sync` 的检查仅只读等待与验收。查看容器状态和镜像拉取日志：

```powershell
docker compose --env-file .env.production -f docker-compose.actions.yml ps
docker compose --env-file .env.production -f docker-compose.actions.yml logs --tail 60 b-mirror
```

可以提供验收 JSON 或错误摘要供诊断；先检查其中没有令牌，不要发送 `.env.production`、完整 Compose 配置或 `docker inspect` 输出。

## 持续运行与停止

`b-mirror` 每 60 秒检查新快照；主应用定时消费漏洞与资料。用另一次真实云端运行再执行验收，才能证明后续更新也正常。电脑关机或 Docker Desktop 停止后，本机网页/API 会停止；GitHub 仍可采集，下次启动会追取新快照。要全天提供服务，需要持续在线机器。

停止部署保留数据：

```powershell
docker compose --env-file .env.production -f docker-compose.actions.yml down
```

不要加 `-v`，不要运行演示初始化覆盖正式数据。端口 8023/8765 被占用时先停止占用程序；与 `docker-compose.production.yml` 的常驻采集模式不能同时启动。

这些脚本兼容 Windows PowerShell 5.1 的语法；仓库侧的静态检查和 Linux 容器验证不能替代你电脑上的 Docker Desktop 实测。真实本机部署结果以该电脑运行的验收 JSON 为准。

## 本轮真实快照验收

2026-10-14，在独立云端 Docker 项目中验证真实 Actions 数据，未生成演示种子：

| 检查 | 实际结果 |
| --- | --- |
| 第 46 代快照 `38515772960` | 自动拉取、严格校验及两路持久消费通过，epoch `53dc8c0640b547e5926bc9555f05ef07`，全局游标 `31614` |
| B API / 主应用重启 | 只读复核通过，数据卷和两路游标保留，没有再次触发导入 |
| 新的第 47 代 `38537353141` | 自动拉取新代成功，两路游标推进至 `33374`，不是重复证明旧快照 |
| 真实数据问答接口 | 返回一条漏洞的证据和回答，引用核对通过，模型未调用；不是问答准确率测试 |

证据完整保存于 [Docker Actions 交付验收 JSON](evidence/docker-actions-delivery-20261014.json)。此隔离验收为便于核查而关闭了主应用自动轮询/富化，并显式同步两个消费者；证明真实快照安装、提供、持久消费、重启与换代，没有证明后台富化、索引完成或持续无人值守。云端 Docker 构建遇到 DNS 限制，验收镜像通过同一锁文件的依赖 wheels 离线构建；标准 Dockerfile 另由 GitHub 容器 CI 验证。

第 47 次真实云采集有一个来源失败、一个部分完成，因此部署同步成功不等于所有上游来源正常或历史积压已经清空。上述结果属于云端隔离机器，不代表你的 Windows 电脑已经部署。Windows 脚本的原生 PowerShell 语法和隔离 mock 流程由 CI 的 `windows-deployment-scripts` 作业核查。
