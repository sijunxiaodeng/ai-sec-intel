# 任务 C：首日证据样例

在仓库根目录运行，Python 3.8 或更新版本即可；这个入口只用标准库，无须安装 requirements.txt、配置密钥或启动 Web：

```powershell
python -m rag.demo
python -m rag.demo --question "CVSS 评分和向量是什么？"
python -m rag.demo --question "受影响版本是什么，如何修复？有没有修复记录？"
python -m rag.demo --json
python -m unittest discover -s questions -p "test_*.py" -v
```

如果电脑上使用 `py` 启动 Python，把命令中的 `python` 换成 `py`。

## 已完成的链路

`enrichment/samples/cve_2024_37032.json` 保存一条历史漏洞输入和三个来源的人工核对摘要。`enrichment.sample.load_sample()` 调用现有 `enrich()`，返回公共接口约定的 EnrichedIntelligence 和文档。

`rag.evidence.save()` 将情报及证据片段写入 `data/task_c.sqlite3`；重复运行更新同一条样例。`search_evidence()` 使用 BM25 检索英文词和中文二元字片段；`rag.answer.answer()` 按问题涉及的主题检索，直接输出证据片段并附上稳定的 evidence_id、来源链接、原文定位和抓取时间。

四个默认演示问题覆盖 AI 关联、版本与修复、利用条件、PoC 验证状态。补充验收还包括 CVSS、跨三个来源的组合回答、未知编号、资产信息缺失和无关问题。部分主题没有证据时返回 partial，没有资料时返回 insufficient_evidence。

## 来源与数据口径

| 来源 | 用途 | 关联类型 |
| --- | --- | --- |
| [NVD 记录](https://nvd.nist.gov/vuln/detail/CVE-2024-37032) | 影响范围、CVSS、Exploit 参考链接 | vulnerability_record |
| [Wiz 原始研究](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032) | AI 关联、技术影响、条件和缓解建议 | direct_analysis |
| [Ollama PR #4175](https://github.com/ollama/ollama/pull/4175) | digest 格式校验修复记录 | fix_record |

样例于 2026-10-08 核对。NVD API 当时收录的 CVSS 3.1 分数为 8.8（HIGH），向量及评分来源标识保存在样例中；条目类型为 Secondary，不写成 NVD 自行计算的评分。0.1.34 是此历史漏洞的修复基线，不能称为当前最新版本，也不能据此保证没有其他漏洞。

每个 chunk 是人工核对的中文摘要，具有 text_kind 和原文定位，少量 excerpt 是短原文摘录。片段的 text_sha256 用于检查文件意外改动，不能证明结论正确。source_response_sha256 是核对时下载的原始 HTTP 响应摘要；完整响应只在开发工作区用于核对，没有复制进仓库，也没有实现完整网页归档。

PoC 仅保留 NVD 标为 Exploit 的候选参考链接。代码没有被下载或执行，validation 为 not_run。该处理状态是本项目记录，不是第三方作者声称代码无效。EPSS、KEV、论文和资产信息未在这一步查询，保留空值；空值不代表不存在风险。

## 可供后续接入的接口

```python
from enrichment.sample import load_sample
from rag.evidence import save, search_evidence
from rag.answer import answer

record, documents = load_sample()
save(record, documents)  # 默认保存到独立的 data/task_c.sqlite3
hits = search_evidence("路径遍历", top_k=3)
result = answer("如何修复？", cve_id=record["item"]["cve_id"])
```

首日 CLI 保留词法检索与抽取式问答基线。多文档组合依据人工主题标签和来源片段；CLI 默认固定在这一条样例上下文，未知编号会拒答。下一步接入见下文。通用产品和资产判断仍需要补充实体识别与资产证据。

公共模型允许扩展的 raw_data.reviewed_facts 保存了富化结论与 evidence_ids。`rag.retrieve.search()` 继续返回整条情报，现附带 evidence_chunks；`search_evidence()` 继续提供首日 BM25 基线。主数据模型、采集器和编排步骤顺序保持兼容。

## 第二步：混合检索与网页问答

使用 Python 3.10 或更新版本，在仓库根目录准备依赖：

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-rag.txt
.venv\Scripts\python.exe -m rag.prepare --semantic
.venv\Scripts\python.exe main.py
```

打开 http://127.0.0.1:8023 ，进入「情报问答」，点击「载入历史演示样例」，再提问。按钮只载入人工样例，不会下载模型或运行联网监测；模型下载发生在显式的 --semantic 准备步骤。

若 Windows 的 Python 下载客户端出现 TLS 超时，可使用 PowerShell 从同一个官方模型仓库下载，然后加载本地目录：

```powershell
& .\rag\download_model.ps1
.venv\Scripts\python.exe -m rag.prepare --semantic --model-dir data/models/bge-small-zh-v1.5-local
```

下载脚本固定官方仓库修订 46fbe35fd4374a00fee7de77dfddaeb6dd6a2c59，并核对仓库提供的 LFS 文件 SHA256；不降低 TLS 校验。

向量检索使用 [FastEmbed](https://qdrant.github.io/fastembed/) 的 [BAAI/bge-small-zh-v1.5 中文模型](https://qdrant.github.io/fastembed/examples/Supported_Models/)，CPU 推理，512 维。BM25 与向量检索的名次通过 RRF 合并；余弦相似度门槛 0.45 是初始工程参数，不是准确率或可信度。SQLite 持久保存片段、向量、模型名称与文本摘要，避免旧向量被用于新证据。查询时只加载本机模型；缺依赖、索引未准备好或文本更新时明确回退到 BM25，重新运行准备命令即可重建。

第二步初始索引覆盖人工核对样例的 8 个片段；第三步可继续自动扩充来源片段。人工主题标签和自动关键词标签辅助多意图召回，不能当作已实现通用多跳推理的证明。资产核验仍需要资产数据。

网页证据区展示完整片段、稳定引用标识、来源链接、原文定位、获取日期和摘要类型。原有 evidence 字段继续返回卡片摘要，新增 evidence_chunks 字段返回片段，旧调用方可继续使用。历史样例不新增为实时监测数据源。

未配置大模型时直接摘录证据；配置现有 DeepSeek/通义兼容接口后，问答会使用片段组织回答。引用标识、编号、显式评分或 PoC 验证状态检查失败时回退到摘录。这些检查不等同于完整的语义事实核验，也没有在本次工作中用真实付费模型接口验证回答质量。

```powershell
.venv\Scripts\python.exe -m pip install -r requirements-test.txt
.venv\Scripts\python.exe -m unittest discover -s questions -p "test_*.py" -v
```

这套测试覆盖混合检索融合、模型不可用回退、证据更新失效、未知范围拒答、引用检查及 API 集成；使用临时数据库，不运行联网采集。原 requirements.txt 的 Pydantic 从 1.10.13 更新为 1.10.26，以兼容本机 Python 3.12 的 ForwardRef 接口；没有迁移到 Pydantic 2。

## 验收及仓库范围

`questions/cve_2024_37032.json` 是根据本样例编写的首日冒烟验收题，不是独立评测集，不能用通过结果宣称竞赛问答准确率。测试全部离线运行并使用临时数据库。

仓库只需保留源码、这份说明、人工核对样例和验收题。生成的 SQLite 数据库、缓存、运行输出、原始网页响应、比赛附件、密钥均不提交。运行后生成的数据库位于已有 .gitignore 排除的 data/ 中。

## 第三步：自动关联资料与证据入库

```powershell
.venv\Scripts\python.exe -m pip install -r requirements-rag.txt
.venv\Scripts\python.exe -m rag.prepare
.venv\Scripts\python.exe -m rag.ingest --cve CVE-2024-37032
.venv\Scripts\python.exe main.py
```

在「情报富化」中选择 CVE，点击「抓取关联资料」，再在「情报问答」限定该编号提问。未配置大模型时展示原文摘录，英文来源保留英文；已有模型设置可组织中文回答。网页对同一来源优先使用自动原文证据，人工摘要继续保留用于首日演示。点击样例按钮只替换人工片段，不清除自动资料。

链路为：现有参考链接 + 对应编号的 NVD API → 关联分类 → HTTP 获取 → 正文/结构化字段提取 → 带来源定位的分块 → SQLite 增量保存 → 本地向量增量更新 → 混合检索与引用回答。

`enrichment/documents.py` 提供获取、提取、关联和分块。HTML 使用 [Trafilatura 的正文提取接口](https://trafilatura.readthedocs.io/en/latest/usage-python.html)，去除导航与评论；NVD、GitHub PR/安全公告、CVE 官方记录和 OSV 优先处理 JSON。不执行正文里的指令、脚本和 PoC。暂支持公开 HTTPS 的 HTML、JSON、纯文本；PDF、登录页面、需要浏览器运行脚本的页面暂不支持，空正文与访问验证页报失败。单响应上限 4 MiB，HTTP 超时 15 秒；超时是请求阶段限制，不能当作整个任务的硬截止时间。

| 关联类型 | 依据 | 问答证据 |
| --- | --- | --- |
| vulnerability_record | NVD 编号完全一致；其他公开漏洞库/公告的正文或标题匹配编号 | 是 |
| direct_analysis | 提取正文或标题出现当前 CVE；URL 本身出现编号不够 | 是 |
| fix_record | 对应 NVD 参考中标为 Patch，或引用了 GitHub PR | 是，修复效果未测试 |
| poc_candidate | 正文/标题匹配编号，且 NVD 参考标为 Exploit | 是，候选代码未执行 |
| background | 没有编号匹配或修复关联依据 | 只存档，不进入漏洞问答 |

这套规则是可审阅的初步关联规则，不是语义准确率保证，也没有搜索全网的所有文章。Wiz 等链接可来自已有人工样例；程序自动获取和提取其正文，链接发现范围仍是现有参考与 NVD。关联文章与学术论文分别处理。未知 CVE 不会触发任意网址抓取；需先通过监测收录，或显式载入历史样例。

`rag.ingest.ingest(record, db_path, max_sources=5)` 每条默认最多处理 5 个来源（含 NVD），允许 1–10；优先修复与编号明确的链接，剩余数量在 `deferred_sources` 报告。监测/公开源富化自动处理本批前 3 条情报、每条最多 4 个来源，防止一次收录拖成无限爬取。详情按钮不受这 3 条限制，默认每次 5 个来源；CLI 可用 `--max-sources 10` 扩大当前记录范围。不会递归爬取网站。

独立证据库保存 `documents`（提取全文与片段）、`source_snapshots`（最近成功的原始响应及摘要）、`document_attempts`（最近尝试状态）、`evidence`（可检索片段）、`embeddings`（向量）。这些表不修改公共数据模型。主知识库与证据库同编号记录在读取时合并参考链接，避免遗漏人工样例已提供的来源。

成功刷新只原子替换同一个来源的旧片段。失败只更新尝试状态，保留上次成功正文与片段；详情显示 `retained_previous/last_success_at`，片段仍标注原获取时间。NVD 临时不可用时，可以沿用此前成功快照的参考关联，并在修复关联说明中标明快照日期。正文或来源变化会更新 SHA256；相同文本和分块重复运行引用 ID 相同，不累积重复证据。响应摘要可以与本地存档响应重新核对，但不能证明内容真实性。

自动主题标签是关键词规则，中文检索标签单独保存在 `search_terms`，没有伪装成原文。分块优先在换行/词边界切分，上限 1000 字符。`locator` 是提取正文/JSON 字段的字符范围，能定位存档文本，不声称是网页行号。网页按版本/CVSS/修复问题优先相应来源类型，并保留另一个来源的证据；这属于检索启发式，需要后续独立评测。HTML 文章日期由提取器推断，不作为监测时效计数依据。

`rag.hybrid.update_index()` 只加载此前显式准备的本机模型，只嵌入新增/变化片段，删除已经移除片段的向量，复用未变向量。模型或索引不可用时报告 `deferred`，证据仍可 BM25 检索；查询检查每段文本摘要，避免静默使用旧向量。可用原 `rag.prepare --semantic` 命令显式准备或重建全部片段索引。

离线测试新增正文去导航、空页拒绝、关联分类、重复与更新、失败保留、原始响应摘要、增量向量、自动编排/API 接入，以及原文方括号与引用区分。真实网站可能超时、拒绝访问或只暴露短摘要；获取成功不代表抓到了该网站的所有内容，失败不表示漏洞没有风险。数据留在本机 `data/`，不把第三方全文或运行报告提交到仓库。

## 第四步：结构化富化与影响评估

`enrichment.assessment` 只读取已有 NVD 和修复来源快照。先核对响应摘要、来源记录的摘要、片段文本摘要及 CVE 编号，再提取带引用的评分、版本范围与候选链接。完整报告由详情页及 `/api/assessment/{cve_id}` 提供；问答根据问题意图附加字段证据，未配置大模型也能输出中文解释。

CVSS 基础向量解释依据 FIRST 的 [v3.1 规范](https://www.first.org/cvss/v3.1/specification-document)、[v3.0 规范](https://www.first.org/cvss/v3.0/specification-document)及 [v4.0 规范](https://www.first.org/cvss/v4.0/specification-document)。解释评分所描述的攻击途径、复杂度、权限、交互及保密性/完整性/可用性影响；v4 额外区分易受攻击系统和后续系统，并解释 AT。暂不重算分数、解释环境/威胁向量或从分数推断业务损失。CVSS 描述技术严重性，具体部署的风险还需要环境信息。

同版本的多个来源评分保留并提示差异，不平均。默认先选更新版本，再选同版本 Primary，这是一项可见的展示规则。真实评分来源和 Primary/Secondary 保留原字段；NVD 是收录入口，不代表所有评分由 NVD 自行给出。

保留 CPE 的包含/排除边界；配置里的非易受攻击依赖不作为漏洞产品列出。AND 或否定条件只提示核对环境，不能据此确认单个资产命中。修复链接沿用此前关联分类，并校验各自来源快照；不把版本排除上界自动变成已确认修复版本。Exploit 标签只生成候选参考，不执行代码。缺少资产、版本与暴露信息时保留具体资产影响未知。

`enrich_view()` 不改写主库历史卡片。报告为即时只读视图，刷新入库时剔除该临时报告，避免辅助记录反复存入过期快照。抓取失败时保留旧证据，并提示日期和状态。字段参考标签可由已校验 NVD 响应形成带 JSON 路径的派生片段；正文引用仍使用原分块位置，不把解释文字伪装成来源原文。

新增离线测试覆盖评分冲突及版本优先、四类基础字段解释、复杂版本配置、字段缺失、快照/片段摘要损坏、刷新失败、只读视图、问答引用和 API。合成测试来源使用临时数据库，不联网或覆盖运行数据。
