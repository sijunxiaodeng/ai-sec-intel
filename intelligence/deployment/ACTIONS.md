# 个人电脑关机后的 GitHub 云端采集

`.github/workflows/intelligence-collect.yml` 使用 GitHub 托管的 Linux runner，每小时第 7、22、37、52 分钟自动执行一次八类来源采集。任务在 GitHub 服务器运行，个人电脑无须开机。默认不调用付费模型；NVD API key 可以配置在仓库 Secret `NVD_API_KEY`，不是启动的必需条件。

工作流只在 `main` 分支执行。定时触发要求这个工作流文件存在于仓库**默认分支**；采集代码明确从原来的 `feat/intelligence` 分支拉取，因此不需要把 A/C 的主应用代码替换为 B 代码。仅把文件留在 B 分支不会启用定时任务。

## 数据如何跨运行保留

每轮先通过 GitHub API 恢复本工作流、同一 `main` 分支最新可信的状态 artifact，然后运行一次采集。整个采集器使用固定并发组，禁止重叠写入，也不取消正在备份的上一轮。来源各有 120 秒超时，四个并发 worker，整轮采集 10 分钟硬截止，任务总截止为 20 分钟。

即使某个来源失败或采集步骤报错，也继续用 SQLite online backup 导出已提交数据，然后上传 `intelligence-state-<run_id>`。快照包含：

- 完整 `intelligence.db`：漏洞、非 CVE 文档、分类结果、增量游标、每源观察基线、HTTP ETag/Last-Modified 缓存和原始首次入库时间。
- `monitoring_baseline.json`、`monitoring_status.json`、`classification_status.json`（存在时）。
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

完全新部署、不迁移任何历史数据时，只有第一次运行允许创建新观察基线；此前关机产生的旧记录不会因此被修改。正式比赛时效应持续记录来源发布时间到首次实际入库的延迟，而不是从工作流启动重新计算漏洞发布时间。

## 查看结果与取回数据

GitHub 仓库 → **Actions** → **B public intelligence collection** 可以查看每轮运行。Summary 显示逐源状态、待补采、数据覆盖以及原始严格六小时时效统计；失败时查看该轮日志。

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
