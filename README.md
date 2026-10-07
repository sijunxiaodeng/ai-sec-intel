# AI 安全知识情报（赛题九）

三人共用的仓库。现在只做一件能演示的事：从 NVD 拉取与 AI 产品相关的漏洞，存成同一张卡片，在页面上按编号或产品名搜到它。

## 怎么打开系统

在本文件夹打开终端：

```
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
