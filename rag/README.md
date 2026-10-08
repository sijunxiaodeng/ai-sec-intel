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

这是词法检索与抽取式问答基线。多文档组合依据人工主题标签和来源片段，还没有实现向量语义检索、自动文章关联、自由推理或大模型生成。CLI 默认固定在这一条样例上下文；未知编号会拒答。通用产品和资产判断需要后续补充实体识别与资产证据。

这一步没有改动主流程、主数据模型、采集器和 Web 问答接口；主系统暂时不会自动展示这个独立样例入口。公共模型允许扩展的 raw_data.reviewed_facts 保存了富化结论与 evidence_ids，便于后续联调。现有 `rag.retrieve.search()` 返回整条情报；新增 `search_evidence()` 返回片段，不改变其返回格式。

## 验收及仓库范围

`questions/cve_2024_37032.json` 是根据本样例编写的首日冒烟验收题，不是独立评测集，不能用通过结果宣称竞赛问答准确率。测试全部离线运行并使用临时数据库。

仓库只需保留源码、这份说明、人工核对样例和验收题。生成的 SQLite 数据库、缓存、运行输出、原始网页响应、比赛附件、密钥均不提交。运行后生成的数据库位于已有 .gitignore 排除的 data/ 中。
