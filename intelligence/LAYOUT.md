# intelligence/ 模块目录（读码地图）

监测能力的**唯一采集与本机库实现**在本目录；主应用根目录只做 HTTP / 编排 / KB / UI 壳。

| 子目录 / 入口 | 职责 | 不该干什么 |
|---------------|------|------------|
| `collectors/` | 多源外网采集（NVD、GHSA、KEV、厂商、RSS、论文、标准…）→ 写入本机库 | 不写主 `knowledge.json`；不做 UI |
| `monitoring/` | 周期编排、来源注册、锁与指标（`multisource` / `source_registry`） | 不替代主 `orchestrator` |
| `storage/` | `intelligence.db`（CVE + 文档） | 不是主 KB |
| `fusion/` | 本机库内 CVE 融合模型 | 不是根 `models.py` 平台契约 |
| `classification/` | 进库前 AI 相关性 | 不是完整 enrichment（C） |
| `api_v6/` | 本机库只读查询 API（经 embed 挂到 :8023） | 不是对外第二端口品牌 |
| `platform_bridge/` | 给主链漏斗用的 OSV + 可选 legacy NVD；根 `collectors/{nvd,osv}` 薄适配 | 不在根目录再复制一套 HTTP/解析 |
| `deployment/` | embed cycle、Actions 同步 | 不抢主 `automation/schedule` 产品定时语义 |
| `incremental/` | 本机库增量游标与窗口 | 与根 `collectors/cursors` 分责 |

产品「一次监测」：`b_monitor` 刷本机库 → `monitor_agent` 读本机库 CVE + 经 facade 调 OSV → 合并入库。
