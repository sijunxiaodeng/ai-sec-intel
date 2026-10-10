# 个人电脑关机后的 GitHub 云端采集

`.github/workflows/intelligence-collect.yml` 使用 GitHub 托管的 Linux runner，每小时第 7、22、37、52 分钟自动执行一次八类来源采集。任务在 GitHub 服务器运行，个人电脑无须开机。仓库已设置 Secret `DEEPSEEK_API_KEY` 后，默认在采集之后运行独立的 DeepSeek 语义复核，每轮最多两次请求；没有该 Secret 时仍执行采集和规则分类。NVD API key 可以配置在仓库 Secret `NVD_API_KEY`，不是启动的必需条件。

工作流只在 `main` 分支执行。定时触发要求这个工作流文件存在于仓库**默认分支**；采集代码明确从原来的 `feat/intelligence` 分支拉取，因此不需要把 A/C 的主应用代码替换为 B 代码。仅把文件留在 B 分支不会启用定时任务。

## 独立的 DeepSeek 语义复核

采集阶段的 `CLASSIFY_V5_MAX_LLM_CALLS` 保持为 `0`：各来源先提交新情报，确定的规则分类先落库，模糊的 AI 候选保留为待复核。之后单独执行 `deployment/deepseek_review.py`，通过固定的 DeepSeek 官方 HTTPS 接口复用现有混合分类器。Secret 仅注入这个模型步骤，不注入采集子进程。

默认模型为 `deepseek-chat`。需要使用账户支持的其他 DeepSeek 模型时，可设置仓库变量 `DEEPSEEK_MODEL`；无需修改或提交密钥。手动 **Run workflow** 时取消 `deepseek_review` 即可关闭该轮模型复核；定时任务默认开启。缺少 Secret 或关闭开关时，模型步骤跳过，并为本轮写入明确的跳过状态。

每轮最多处理两次模型请求，失败尝试也占预算。单请求设置 20 秒连接/读取超时，模型子进程组另有 60 秒绝对截止。模型超时、认证失败或响应校验失败不会改变已提交的采集数据、来源游标或采集结果，也不会阻止后续快照上传；截止前已提交的分类仍被保留。待复核和失败项保持 `unknown/null`，不会冒充已确认的非 AI 结论。

模型复核范围是统一漏洞表中规则无法确定的 **CVE 记录**，不会重新判断每一篇博客、论文、标准或政策文档，也不会逐条复核规则已确定的漏洞。`deepseek_status.json` 记录本轮模型、尝试数、通过响应校验的成功数、失败类型以及已提交结果数；成功响应数与已落库结果数分别统计。状态文件和日志不保存密钥、认证头、完整异常或模型原始响应。

新增模型步骤不重置历史 `first_seen_at`、发布时间、观察基线或六小时超限记录。发布到首次入库的采集时效与语义复核队列的等待时间是两个指标；开启 DeepSeek 本身不能证明严格 `<6h` 已通过。

## 数据如何跨运行保留

每轮先通过 GitHub API 恢复本工作流、同一 `main` 分支最新可信的状态 artifact，然后运行一次采集。整个采集器使用固定并发组，禁止重叠写入，也不取消正在备份的上一轮。来源各有 120 秒超时，四个并发 worker，整轮采集 10 分钟硬截止，任务总截止为 20 分钟。

即使某个来源失败或采集步骤报错，也继续用 SQLite online backup 导出已提交数据，然后上传 `intelligence-state-<run_id>`。快照包含：

- 完整 `intelligence.db`：漏洞、非 CVE 文档、分类结果、增量游标、每源观察基线、HTTP ETag/Last-Modified 缓存和原始首次入库时间。
- `monitoring_baseline.json`、`monitoring_status.json`、`classification_status.json`、`deepseek_status.json`、`actions_report.json`（存在时）。
- 带仓库、分支、运行 ID、文件大小和 SHA-256 的清单。

快照不包含 `.env`、密钥、PID、进程锁、源日志或虚拟环境。artifact 保存期限为 90 天，但**成功上传新状态后只保留最近八份本工作流可信快照**，避免每 15 分钟重复保存大数据库而长期累积。清理使用 `actions: write`；采集代码、状态恢复默认使用 `contents: read`。其他工作流、其他分支的 artifact、初始 Release 种子均不清理。

若上轮已经采集但快照丢失、过期、校验不通过，任务会停止，而不是重新创建空库、重置首次入库和超限记录。历史 run 不能使用 GitHub 的 **Re-run jobs** 继续写库；请使用 **Run workflow** 创建新运行，以免回放旧 run 导致状态回滚。非 `main` 分支手动触发会跳过采集。

## 迁移已有数据，保留原来的时效记录

首次启动支持同一个 GitHub 仓库的 Release 种子，输入是 `bootstrap_release_tag`，也可设置仓库变量 `INTELLIGENCE_BOOTSTRAP_RELEASE_TAG`，以便首次部署失败后下一个定时运行可以自动重试。固定资产名必须为 `intelligence-bootstrap-state.zip`。程序不接受其他仓库或任意 URL 的种子。

制作种子前停止写入进程，或在写入进程的外部锁内使用 SQLite online backup，并确认相关基线 JSON 一致。示例：

```bash
python intelligence/deployment/actions_state.py save \
  --source intelligence/data --directory /tmp/intelligence-initial-state \
  --repository sijunxiaodeng/ai-sec-intel --branch main --run-id 0
```

将这个目录的直属文件压缩成 `intelligence-bootstrap-state.zip`，上传到同仓库的专用 Release。种子仅在此前没有运行写入采集库、且没有可用 artifact 时读取；一旦上传首个状态 artifact，后续总是恢复 artifact，种子不能用于覆盖新的状态。

如果种子采用 **draft Release**，GitHub 只向有仓库写权限的身份暴露 draft。首次初始化的 `main` 工作流可临时使用 `contents: write`；验证首次上传及第二次从 artifact 恢复成功后，立即降回 `contents: read`。脚本通过列举 Release 并匹配 `tag_name` 读取 draft，找不到或不可读时会停止，不能偷偷创建新空库。B 分支模板始终保持 `contents: read`。

### 不使用 Release 上传的迁移方式

也可以把同一份已校验的 `intelligence-bootstrap-state.zip` 放在**同仓库专用种子分支的根目录**，仅提交这个公开来源数据文件。手动运行时填写 `bootstrap_state_commit`，或设置仓库变量 `INTELLIGENCE_BOOTSTRAP_STATE_COMMIT`，其值必须是该提交的完整 **40 位十六进制 commit SHA**；不能填写分支名、短 SHA、其他仓库或下载 URL。

脚本先验证该 SHA 确实是本仓库的 Git 提交，再通过 GitHub Contents API 的 raw 表示读取固定路径 `intelligence-bootstrap-state.zip`；清单仍必须匹配本仓库、`main`、初始 run ID `0`。这种迁移仅需 `contents: read`。artifact 总是优先；还未有任何采集写入时，Git 提交种子优先于可选 Release 种子。两个种子均不用于覆盖后续运行的新数据。

种子分支仅用于一次迁移，不能包含 `.env`、密钥、用户私有资产或私人数据。公共仓库的 Git 种子也是公开文件，因此必须先审核数据。提交 SHA 固定后，新增快照不改变初始种子的身份；后续采集仍只读最新 artifact，不向种子分支提交周期性数据库。

完全新部署、不迁移任何历史数据时，只有第一次运行允许创建新观察基线；此前关机产生的旧记录不会因此被修改。正式比赛时效应持续记录来源发布时间到首次实际入库的延迟，而不是从工作流启动重新计算漏洞发布时间。

## 查看结果与取回数据

GitHub 仓库 → **Actions** → **B public intelligence collection** 可以查看每轮运行。Summary 显示本轮模型尝试与响应校验数、逐源状态、待补采、数据覆盖和实际运行间隔。去重 CVE 的时效分别显示原始完整观察期、首次云端部署后和最近 24 小时，三个范围不会互相替代；逐源记录数另外显示，不能当作去重后的漏洞数。首次云端部署时间固定为已核实的 `2026-10-09T12:05:16Z`，不会写回原观察基线。

`deployment/actions_report.py record` 在采集和模型复核后只读数据库，写出与当前 `run_id` 对应的 `actions_report.json`，并输出只含安全状态和数字的 `B cloud facts` 通知。最后的 `summary` 只读取同一运行的报告；恢复出的旧报告或旧模型状态不会冒充本轮结果。报告故障不阻止已采集数据备份。

个人电脑重新开机后，可以从最近一次可信运行下载 `intelligence-state-<run_id>` artifact，在 B 数据目录为空且旧进程已停止时恢复。先把旧 `data/` 留作备份，不覆盖仍在运行的数据库：

```bash
python intelligence/deployment/actions_state.py restore-file \
  --archive /path/to/intelligence-state-123456.zip \
  --directory intelligence/data \
  --repository sijunxiaodeng/ai-sec-intel --branch main --run-id 123456
```

恢复命令校验来源和文件哈希，保留原始时间戳。之后可以按 B 的 README 启动本地 API，提供新数据给 A/C。Actions 负责定时采集和备份，**不托管常驻 API、网页、问答模型或 A/C 的后台服务**。

## 时效边界

每 15 分钟是调度目标，GitHub 明确可能延迟或丢弃繁忙时的定时任务；公开仓库长期没有活动时也可能自动停用 schedule。任务启动频率、上游 API 的收录延迟、分页补采、GitHub 网络和来源失败均影响实际时效。此版本消除了个人电脑关机的依赖，但不能仅凭部署成功认定严格 `<6h` 指标通过。已有超限数据应保留，后续通过 Summary 和真实时间戳验证改进。
