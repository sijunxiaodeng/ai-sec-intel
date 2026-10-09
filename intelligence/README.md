# B：AI 安全情报采集与筛选

B 已实现多源采集、CVE 融合与分类、非 CVE 文档存储和独立只读 API。默认目录包含 **11 个来源、8 类内容**，持续监测默认每 15 分钟运行一轮。当前目标是实际覆盖至少 7 类 AI 安全情报，并证明新漏洞从原始发布时间到首次入库的延迟 **严格小于 6 小时**。

真实采集已覆盖八类主题内容：文档 561 条，NVD、GitHub 和 CISA 均已入库。恢复采集的观测记录中仍有严格六小时超限样本，不能声称时效已验收通过；逐源详情和快照数字见 [运行验证.md](运行验证.md)。团队监测已注册 `IntelligenceCollector`。主程序采集时会请求本机 `http://127.0.0.1:8765/api/intelligence/team`，所以要先在本目录启动只读 API，主页面才会收到 B 的 CVE。非 CVE 文档仍需 A/C 接入主知识库、检索与问答。

## 安装

Python 3.10 或更新版本；此前本地验证使用 Python 3.12。B 的 FastAPI 版本与仓库根目录旧版本不同，使用独立虚拟环境，不覆盖队友的依赖环境。

在仓库根目录进入 `intelligence`，除容器命令外，后续命令均在此目录执行：

```bash
cd intelligence
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock.txt
test -f .env || cp .env.example .env
```

Windows PowerShell 将激活命令改为 `.venv\Scripts\Activate.ps1`；也可直接用 `.venv\Scripts\python.exe` 代替后续的 `python`。`requirements_v6.txt` 描述直接依赖，`requirements.lock.txt` 保存已验证的完整版本。保留已有 `.env`，不要提交凭据。

公开来源可先用无密钥请求验证。已有 NVD/GitHub 凭据用于对应接口的认证或配额，应先复用现有配置；GitHub 仓库可读取不代表 Advisory API 已获网络放行，代理 `403` 不直接说明缺少 Token。

每轮采集结束后默认执行 CVE V5 规则分类，最多处理 300 条，模型预算为 0；无法由规则确定的条目保留待判断状态。填写兼容模型接口并明确增加 `CLASSIFY_V5_MAX_LLM_CALLS` 才会发送模型请求。`AUTO_CLASSIFY_V5=0` 可关闭自动分类。分类子进程有独立超时，分类失败不撤销已落库数据或推进失败的来源游标。

## 内容类别与默认来源

类别按内容来源及用途划分，RSS、API、网页属于获取方式。多个站点或同一公告的多个副本不会自动增加类别。

| 内容类别 | 默认来源 | 采集目标与边界 |
| --- | --- | --- |
| 漏洞数据库 `vulnerability_database` | `NVD`、`GITHUB_ADVISORY` | NVD CVE API、GitHub 全球 Advisory API；两者合计一类，全球 Advisory 不重复算社区或厂商公告 |
| 安全社区 `security_community` | `HF_SECURITY_COMMUNITY` | Hugging Face 社区 `latest.rss`，保留安全主题帖子；作为独立社区来源 |
| 厂商公告 `vendor_advisory` | `VLLM_VENDOR`、`OLLAMA_VENDOR`、`LANGCHAIN_VENDOR` | 对应项目的 GitHub repository security-advisories API，保留仓库级厂商来源证据；三个项目合计一类 |
| 技术博客 `security_blog` | `TRAIL_OF_BITS_BLOG` | Trail of Bits 官方 feed，本地过滤 AI 与安全主题 |
| 学术论文 `academic_paper` | `ARXIV_AI_SECURITY` | arXiv 官方 API 的 AI 安全查询，校验全部分页；默认滚动查询最近 7 天提交的论文 |
| 技术标准 `technical_standard` | `NIST_CSRC_AI_STANDARDS` | 从 NIST CSRC AI 主题出版物检索目录发现正式标准、指南等出版物，再读取官方详情页；目录页本身不算标准 |
| 政策法规 `policy_regulation` | `FEDERAL_REGISTER_AI_POLICY` | Federal Register 官方 documents API，按 AI 检索并过滤安全、治理、隐私等主题，校验分页完整性 |
| 政府告警 `government_alert` | `CISA_KEV` | CISA 已知被利用漏洞目录，主站请求失败时使用 CISA 官方 `cisagov/kev-data` 镜像；`dateAdded` 是收录日期，不是漏洞发布日期 |

来源定义在 `monitoring/source_registry.py`。各类已有真实入库证据，Ollama 厂商公告成功返回零条，不额外增加实际覆盖；最近 arXiv 请求失败，先前 318 条论文保留。这些结果不保证上游持续可达、接口长期兼容或采集范围完整。

默认来源及 CISA 官方镜像需要以下 9 个 HTTPS 域名：

```text
services.nvd.nist.gov
api.github.com
www.cisa.gov
discuss.huggingface.co
blog.trailofbits.com
export.arxiv.org
csrc.nist.gov
www.federalregister.gov
raw.githubusercontent.com
```

前八个域名的网络增补已写入云环境配置草稿，`raw.githubusercontent.com` 已在包管理预设允许列表。当前实例已成功访问各类上游；CISA 主站仍返回 403，官方镜像可用，arXiv 存在请求超时。安装、启动及两仓库挂载也已保存为可复用配置草稿；草稿保存不等于发布，仍需在环境设置保存并发布才能在新实例复用。使用自定义来源或模型时另需相应域名，并验证具体服务。

## 采集与持续监测

默认持续运行；单轮验证使用 `--once`：

```bash
python run_monitor.py --once
python run_monitor.py
```

默认参数为每 15 分钟开始一轮、4 个并行 worker、每源子进程 120 秒超时。来源失败或超时独立记录，不阻止其他来源落库，下一轮重新尝试。进程锁防止同一数据目录同时运行两轮；超时停止该来源子进程，已提交数据保留。`--max-runs 2` 限制轮数，Ctrl+C 退出。

NVD/GitHub 先采集最近 12 小时新发布窗口并落库，再通过修改时间处理独立历史回填游标，避免旧漏洞批量更新挡住新发布信息。首次回填默认最近 7 天，每轮默认推进一个小时窗口；窗口完整落库后才推进游标，回填失败不撤销已提交的近期阶段。NVD 每页默认 500 条；GitHub 查询按 API 支持的整秒向外扩展边界，本地游标保留原精度，避免小数秒导致 422 或漏采。CISA 使用完整快照和内容去重。文档使用稳定来源 ID、内容哈希、事务和可用的 ETag/Last-Modified 缓存；失败不保存新的 HTTP 检查点，空批次或 304 不删除历史文档。

`partial` 表示部分来源失败或历史窗口仍积压，应检查 `data/monitoring_status.json`、来源日志和覆盖接口。单轮退出码 0 不能替代逐源成功验收，也不能证明 SLA。不要绕过分页预算跳过窗口；增加合理预算或继续重试消化积压。分类结果另查状态文件及 `data/classification.log`，采集成功不表示分类已全部完成。

常用运行覆盖如下；环境变量可调整默认值：

| 参数或变量 | 默认值 | 用途 |
| --- | --- | --- |
| `--interval-minutes` / `MONITOR_INTERVAL_MINUTES` | 15 | 轮询周期，必须大于 0 且小于 360 分钟 |
| `--workers` / `MONITOR_WORKERS` | 4 | 独立来源并行数，1–16 |
| `--source-timeout` / `SOURCE_TIMEOUT_SECONDS` | 120 | 单源总超时，必须大于 0 且小于 21600 秒 |
| `RECENT_LOOKBACK_HOURS` | 12 | NVD/GitHub 近期修改窗口 |
| `VULNERABILITY_BOOTSTRAP_DAYS` | 7 | 新多源入口的漏洞首次回填范围 |
| `BACKFILL_MAX_WINDOWS` / `RECENT_MAX_PAGES` / `BACKFILL_MAX_PAGES` | 1 / 4 / 4 | 单轮历史窗口及两阶段分页预算 |
| `BACKFILL_WINDOW_HOURS` | 1 | 修改时间回填窗口大小，避免整周数据超过分页预算 |
| `PAPER_LOOKBACK_DAYS` | 7 | arXiv 提交日期滚动窗口 |
| `AUTO_CLASSIFY_V5` / `CLASSIFY_V5_MAX_ITEMS` / `CLASSIFY_V5_MAX_LLM_CALLS` | 1 / 300 / 0 | 每轮自动 CVE 分类、条数预算和模型调用预算 |

启动时联合校验轮询周期、稳定等待和整轮采集最坏预算之和严格小于六小时；默认预算为 15 分钟轮询 + 5 分钟稳定等待 + 7.5 分钟整轮超时/分类预算。首次入库时间在拿到写锁并完成融合后记录，避免锁等待和处理时间被漏算。健康报告使用最后提交的运行记录，失败不会被之前成功覆盖；新鲜度阈值考虑并发来源排队。

arXiv 默认窗口覆盖新提交和这些近期论文的重查，**不覆盖所有旧论文的新修订**。RSS 上游保留窗口、分页预算、来源自身迟发布和网络中断也影响实际完整性与时效，15 分钟轮询本身不能保证所有漏洞小于 6 小时。

可用 JSON 替换默认来源目录：

```bash
export INTELLIGENCE_SOURCE_CONFIG=/absolute/path/sources.json
python run_monitor.py --config "$INTELLIGENCE_SOURCE_CONFIG" --once
```

文件可为来源对象数组，或仅含 `sources` 数组的对象。每个来源使用 `name/category/kind/url/content_type/options/enabled` 等 `SourceSpec` 字段；自定义配置替换默认目录，可能少于七类。API 进程必须使用相同的 `INTELLIGENCE_SOURCE_CONFIG`，否则覆盖报告按另一份目录计算。API 启动入口也读取 B 的 `.env`；显式进程环境优先。不要在 URL 或配置文件中嵌入密钥。

`run_monitor_once.py` 是保留的旧三源入口，仅采集 NVD/GitHub/CISA，可兼容旧部署；它的单次运行与 `--interval-minutes 60` 不覆盖新增文档来源。新部署使用 `run_monitor.py`。

旧版数据库先停写并备份（建议使用 SQLite backup API；直接复制时需正确处理 WAL），再执行：

```bash
python run_rebuild_unified.py
python run_ai_classification_v5.py --max-items 300 --max-llm-calls 0
```

重建仅重新融合已有 CVE 原文，不联网、不删除采集历史，可重复执行。旧融合结果补全来源证据并修正 CISA 日期；内容哈希变化后旧分类自动失效，需要重新分类。首次新采集不需要额外重建。

`run_ai_classification_v5.py --preview 10` 不调用模型、不写分类结果，但会初始化分类表；`--stats` 查看当前内容哈希与分类器版本匹配的结果。`review` 不是已确认正例，语义失败或无预算不是非 AI 结论。

## 查询与团队接入

另开终端，使用同一 B 虚拟环境、数据库和来源配置：

```bash
python run_intelligence_api_v6.py --host 127.0.0.1 --port 8765
```

API 不会启动监测。默认数据库为 `data/intelligence.db`；监测的 `--db` 与 API 的 `INTELLIGENCE_DB_PATH` 必须指向同一文件。没有数据库时返回 503；仅采集而未建 CVE 分类表时可查询，分类显示未知。旧数据库没有文档表时文档列表和统计降级为空，不由只读 API 建表。

| 路径 | 用途 |
| --- | --- |
| `/api/intelligence` | CVE 分页查询，支持 `q/source/state/ai_related/category` |
| `/api/intelligence/ai` | 当前有效、已完成分类的 AI 正例，排除待复核结果 |
| `/api/intelligence/{cve_id}?include_raw=true` | CVE 完整来源、CVSS 证据及原文 |
| `/api/intelligence/team` | 团队 `IntelligenceItem` 字段，默认只导出当前有效、已完成分类的 AI 正例 |
| `/api/intelligence/stats` | CVE 分类与采集数量，待复核正例单独统计 |
| `/api/intelligence/health` | 数据库可查询性及最近采集/分类状态 |
| `/api/intelligence/metrics` | CVE 发布到首次入库的延迟及严格小于六小时的样本统计 |
| `/api/intelligence/coverage` | 配置类数、实际入库类数、AI 相关类数、逐源健康和精确时间的实时样本证据 |
| `/api/documents` | 非 CVE 文档分页查询，支持 `q/source/category/content_type/cve_id`，可显式请求原文 |
| `/api/documents/stats` | 实际文档、来源、内容类别和最近采集状态统计 |
| `/api/documents/{document_id}?include_raw=true` | 文档详情、可选关联 CVE、来源原文与时间证据 |

文档保留 `document_id/source/source_category/content_type/title/description/url/published_at/modified_at/cve_ids`，以及首次入库、最近观察、内容更新时间和原始来源证据；没有 CVE 的论文、标准、政策或文章不会被丢弃，也不会伪造 CVE。

团队 CVE 接口可用 `ai_only=false` 查询全部漏洞；`include_review=true` 显式纳入待复核正例，标记在 `raw_data.classification`。缺少的信息留空，不推断不存在的修复版本或 CVSS 版本。A 在根目录可以调用：

```python
from collectors.intelligence import IntelligenceCollector
items = IntelligenceCollector(keyword="ollama").collect()
```

该适配器读取 B 本地 HTTP 服务，返回团队已有模型格式。A 仍需将其注册到主监测/编排流程。非 CVE 文档 API 已实现，但主系统的数据模型、富化、索引和问答尚需 A/C 接入；CVE 卡片适配器不能自动完成该工作。保持独立进程，通过 HTTP 交接，避免在一个进程直接导入两套同名顶层 `collectors` 包。

## 容器运行与运行证据

在仓库根目录运行：

```bash
docker compose -f intelligence/compose.yml up -d --build
docker compose -f intelligence/compose.yml ps
docker compose -f intelligence/compose.yml logs -f
```

`intelligence/Dockerfile` 只构建 B，容器工作目录为 `/app`。Compose 的 `monitor` 和 `api` 服务分别运行默认 15 分钟多源监测和 8765 API，两者共享 `/app/data` 的 SQLite、状态和日志数据卷；宿主机 API 仅绑定 `127.0.0.1:8765`。该部署不启动团队主应用、不自动注册 A/C 适配器，也不提供尚未集成的非 CVE 问答。停止使用 `docker compose -f intelligence/compose.yml down`；保留数据卷，不使用 `down -v` 清除观测证据。

可选 `.env` 的 Compose 写法需要 Docker Compose 2.24 或更新。当前云实例 Docker 构建网络存在 DNS 限制；使用相同锁定依赖的离线 wheel 构建验证容器运行，普通联网构建应在具备容器网络的部署机验证。当前实例实际持续服务使用 B 的独立虚拟环境，PID 和日志在 `data/api.pid`、`data/daemon.pid`、`data/api.log`、`data/daemon.log`；云实例关闭后需重新启动服务。

宿主机运行也需持续保持监测与 API 进程，可交给 systemd 或其他服务管理器。容器重启策略、日志和状态接口只是运维基础，还需配置来源级失败/超时/积压告警并验证重启恢复。单轮自动分类有条数和时间预算，积压较多时另行运行分类 CLI；时效指标只衡量首次入库，不表示全部分类已完成。

## 验证与严格时效口径

```bash
python -m unittest discover -s tests -v
python -m pip check
```

离线测试覆盖分页完整性、失败不推进游标、跨来源融合、事务回滚、模型结果校验、队列预算、分类过期、只读 API 降级、团队转换；新增文档测试覆盖稳定 ID、无 CVE 文档、来源类别、缓存、官方分页及日期精度，覆盖报告测试区分配置、空轮询、实际内容和严格六小时边界。端到端样本为明确标注的离线合成数据，会实际运行分类 CLI 和本地 HTTP API；不请求外部采集源或付费模型。测试通过不能替代真实来源覆盖、分类质量或线上 SLA。

`monitoring_baseline.json` 和逐源观察基线只记录首次观察起点，**不证明进程从该时刻起一直在线**。实时延迟只纳入基线之后发布、具有可信精确时间并首次入库的样本；历史回填另列。CISA 收录日期、仅日期、缺少时区/时间、未来时间和负延迟不作为小时级达标证据；NVD 文档明确为 UTC 的时间按其来源约定解析。

严格判定使用原始秒数：`delay < 21600` 才达标，`delay >= 21600` 是违约，恰好六小时也算违约，不能按四舍五入后的小时值判断。CVE 指标的 `under_6h/breached_6h` 用于当前目标，兼容字段 `within_6h` 的“≤6 小时”不够严格。CVE 指标按漏洞统计；覆盖报告另提供逐来源入库延迟，包含尚未完成 AI 分类的记录，两者不能互相替代，也不衡量分类、富化或问答完成时间。

验收至少需要 `observed_ai_category_count >= 7` 的真实内容并逐类核对来源、可信精确时间的新漏洞实时样本、零严格六小时违约及可解释的未知时间记录，还需连续运行、失败恢复和漏采检查证据。文档的 AI 数量是来源采集器过滤出的主题候选，不能作为测得的分类准确率。配置八类、成功空轮询、无样本、历史回填或仅有日期都不能证明达标；已观察样本达标也不能保证未知、漏采、上游迟发布或未来内容的时效。

更多赛题对照、团队责任及待验证项见 [赛题差距与交接.md](赛题差距与交接.md)。
