# AI 安全知识情报（赛题九）

三人共用的仓库。目前支持 NVD/OSV 漏洞监测、关联资料抓取与证据入库、结构化富化与影响说明，以及带来源引用的检索问答。

## 怎么打开系统

在本文件夹打开终端：

```
python -m pip install -r requirements.txt
python main.py
```

浏览器访问 http://127.0.0.1:8023 。页面里可以监测、查看富化、提问，并在「模型设置」里填写 DeepSeek 或通义千问的兼容接口。

接口约定见 `接口说明.md`。

## 怎么重新采集

在本文件夹打开终端：

```
python collect_nvd.py
```

需要能访问 NVD，第一次可能要等一分钟。成功后再双击 `page.html`。

## 三人分工

| 人 | 负责 | 不要改 |
| --- | --- | --- |
| A | `models.py`、`store.py`、`orchestrator.py`、`page.html` | 采集细节、问答题 |
| B | `collectors/` 里的来源。返回的字典必须能被 `models.normalize` 收成卡片 | `orchestrator.py` |
| C | 从原文抄 CVSS 和受影响版本；`questions/` 里的题目 | `orchestrator.py` |

同一条漏洞用 `cve_id` 合并成一张卡。原文没有的分数或版本留空，不要编。

三人怎么拉取、提交和推送，看 `协作说明.md`，或同目录的 `协作说明.docx`。

## 分支

- `main`：能演示的稳定版本
- `dev`：三人往这里合
- 各自从 `dev` 拉分支，例如 `feature/collector`、`feature/enrich`

不要把密钥写进仓库。

## 任务 C 的首日证据样例

在仓库根目录运行 `python -m rag.demo`，可离线演示 CVE-2024-37032 的富化样例、证据入库、检索和带引用的抽取式问答。它使用 Python 标准库，无须大模型密钥；样例明确标注人工整理，PoC 尚未由本项目复现。

运行和验收说明见 [rag/README.md](rag/README.md)。网页的「情报问答」现可载入历史样例，查看跨文档回答、片段引用及来源。

需要本地中文向量检索时，使用 Python 3.10 或更新版本，执行：

```powershell
python -m pip install -r requirements-rag.txt
python -m rag.prepare --semantic
python main.py
```

首次准备会下载模型。向量索引尚未就绪时，页面会明确显示使用 BM25。Windows 下载替代入口及测试方法见 [rag/README.md](rag/README.md)。

## 第三步：自动处理关联资料

打开「情报富化」，选择一条 CVE，点击「抓取关联资料」。页面会显示各来源的关联类型、抓取状态和片段数；随后可以在「情报问答」按这个编号提问。也可运行：

```powershell
python -m rag.ingest --cve CVE-2024-37032
```

这一步从现有参考链接和对应 NVD 记录发现资料，自动提取正文、分块、保存来源快照，并增量更新已准备的本地向量索引。未准备模型时仍可使用 BM25；不会在抓取或提问时下载模型。监测与公开源富化完成后，自动处理本批前 3 条情报，每条最多 4 个来源；其他情报可在详情页逐条处理。

完整原文、数据库、运行报告和模型留在被忽略的 `data/` 中。仓库只提交源码、接口与运行说明、离线测试。关联规则、支持范围和失败处理见 [rag/README.md](rag/README.md#第三步自动关联资料与证据入库)。

## 第四步：结构化富化与影响评估

完成关联资料抓取后，在「情报富化」选择对应 CVE，详情自动显示 CVSS 版本、分数、评分提供者与向量、受影响版本范围、攻击条件和技术影响、修复记录与 PoC 候选状态。每项事实附来源字段定位；「情报问答」也使用这些字段，例如提问「CVE-2024-37032 的 CVSS 评分、受影响版本和利用条件是什么？」。

报告读取本机已存档并校验 SHA256 的 NVD 响应，不额外联网、不需要大模型密钥。它保留所有有效评分，展示默认优先顺序为 CVSS 4.0、3.1、3.0、2.0，同版本优先 Primary；不同来源的评分不取平均分。NVD 收录的厂商评分保留真实提供者，不能统称为 NVD 自行评分。

版本包含/排除边界分别保留；版本范围的排除上界不直接认定为修复版本。PoC 候选只说明来源有 Exploit 标签，未运行；修复记录未由本项目测试。缺少资产清单与部署信息时，具体资产影响显示未知。目前不重新计算 CVSS 或环境评分。

接口 `GET /api/assessment/{cve_id}` 返回同一报告。测试命令：

```powershell
python -m pip install -r requirements-test.txt
python -m unittest discover -s questions -p "test_*.py" -v
```

报告字段与解释依据见 [接口说明.md](接口说明.md) 和 [rag/README.md](rag/README.md#第四步结构化富化与影响评估)。
