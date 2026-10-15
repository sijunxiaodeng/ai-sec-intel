"""Preliminary rubric and operational signals with their actual denominators."""
from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import time

from acceptance import evidence

CATEGORY_LABELS = {
    "vulnerability_database": "漏洞数据库", "security_community": "安全社区",
    "vendor_advisory": "厂商公告", "security_blog": "安全博客", "academic_paper": "学术论文",
    "technical_standard": "技术标准", "policy_regulation": "政策法规", "government_alert": "政府预警",
}
RUBRIC = [
    ("monitoring", "情报监测功能", 15, "来源类别 3 / 5 / 7 类；优秀还要求实时监测", "monitor"),
    ("enrichment", "情报富化功能", 15, "至少 3 种 / 5 种以上维度；优秀要求准确及自动关联推理", "enrich"),
    ("qa_function", "情报问答功能", 15, "基础检索 → 语义理解与多轮 → 跨文档推理与深度分析", "ask"),
    ("latency", "监测时效", 5, "发布到采集延迟 ≤24 / ≤12 / ≤6 小时", "observation"),
    ("enrichment_accuracy", "富化准确率", 5, "≥70% / ≥85% / ≥95%；按事先确定的事实单元核对", "quality"),
    ("qa_accuracy", "问答深度与准确率", 5, "基础准确率 ≥70%；深度问答含推理链；多跳准确率 ≥85%", "quality"),
    ("agents", "智能体架构", 15, "Agent 使用、多角色协作、自主编排及可扩展性", "risks"),
    ("automation", "系统自动化", 10, "核心流程自动化 → 全流程与异常处理 → 自愈能力", "monitor"),
    ("documentation", "文档质量", 15, "报告 Word+PDF、操作演示视频、讲解 PPT 的 PDF；设计图与实现说明", "evidence"),
]


def _read_connection(path):
    connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
    connection.row_factory = sqlite3.Row
    deadline = time.monotonic() + 2
    connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 5000)
    connection.execute("PRAGMA query_only=ON")
    connection.execute("BEGIN")
    return connection


def runtime_signals():
    from api.b_embed import db_path
    from database.store import database_path
    from automation.schedule import state
    result = {"source_categories": [], "source_records": [], "field_coverage": None,
              "processing": [], "agent_runs": None, "errors": [], "monitor": state()}
    try:
        with closing(_read_connection(db_path())) as connection:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "source_observation_baselines" in tables:
                rows = connection.execute("SELECT source,source_category FROM source_observation_baselines ORDER BY source").fetchall()
                result["registered_sources"] = [dict(row) for row in rows]
                grouped = {}
                for row in rows:
                    grouped.setdefault(row["source_category"], []).append(row["source"])
                result["source_categories"] = [{"category": key, "label": CATEGORY_LABELS.get(key, key),
                                                "sources": values} for key, values in grouped.items()]
            for table in ("source_items", "knowledge_documents"):
                if table in tables:
                    result["source_records"].extend({"source": row[0], "records": row[1], "table": table}
                        for row in connection.execute(f"SELECT source,COUNT(*) FROM {table} GROUP BY source"))
            if "model_review_runs" in tables:
                result["model_review_runs"] = connection.execute("SELECT COUNT(*) FROM model_review_runs").fetchone()[0]
    except (sqlite3.Error, OSError):
        result["errors"].append("来源库暂不可读取；不将缺失值计为零或成功")
    try:
        with closing(_read_connection(database_path())) as connection:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "knowledge_records" in tables:
                counts = {key: 0 for key in ("cvss", "epss", "kev", "papers", "affected", "poc")}
                live = 0
                for row in connection.execute("SELECT payload_json FROM knowledge_records"):
                    record = json.loads(row[0])
                    item = record.get("item") or {}
                    if (item.get("raw_data") or {}).get("sample_mode"):
                        continue
                    live += 1
                    for key in counts:
                        value = record.get(key) if record.get(key) is not None else item.get(key)
                        if value is not None and value != [] and value != "":
                            counts[key] += 1
                result["field_coverage"] = {"live_records": live, "counts": counts,
                                             "present_dimensions": sum(value > 0 for value in counts.values()),
                                             "note": "字段存在率，不是富化准确率；版本字段不等于真实资产已受影响"}
            if "processing_jobs" in tables:
                result["processing"] = [dict(row) for row in connection.execute(
                    "SELECT stage,status,COUNT(*) count FROM processing_jobs GROUP BY stage,status")]
            if "processing_runs" in tables:
                result["agent_runs"] = connection.execute("SELECT COUNT(*) FROM processing_runs WHERE stage='investigate'").fetchone()[0]
    except (sqlite3.Error, OSError, ValueError, TypeError):
        result["errors"].append("主库统计暂不可读取；待处理任务不等于功能失败或已完成")
    result["source_scope_note"] = "类别为已登记来源配置；原始记录含尚未判定 AI 相关性的记录，不能直接当作目标样本覆盖率"
    return result


def summary():
    from acceptance.quality import list_runs
    from acceptance.observation import list_windows
    from acceptance.worker import state as worker_state
    signals = runtime_signals()
    files = evidence.catalog()
    quality = list_runs()
    observations = list_windows()
    counts = signals.get("field_coverage") or {}
    descriptions = {
        "monitoring": (f"登记 {len(signals['registered_sources'])} 个来源、{len(signals['source_categories'])} 类；实际成功/失败看各轮记录"
                       if "registered_sources" in signals else "来源登记统计暂不可用；不能据此判定覆盖情况"),
        "enrichment": f"已有 {counts.get('present_dimensions', '未知')} 类非空字段；范围与正确性需逐事实复核",
        "qa_function": "基础、会话、跨文档链路可检查；题目正确与否看冻结评测和引用证据",
        "latency": "观察窗口、迟到、漏采及成熟等待分别展示；轮询间隔不等于采集延迟",
        "enrichment_accuracy": "从原始漏洞与参考来源逐事实审核；未审样本留在分母中",
        "qa_accuracy": "自动规则检查与按声明独立人审分别展示；基础和多跳分组计算",
        "agents": (f"已记录 {signals['agent_runs']} 次调查运行；可在资产风险查看模型决策、工具结果和停止原因"
                   if signals['agent_runs'] is not None else "调查运行计数暂不可用；可在资产风险查看已有工具轨迹"),
        "automation": "显示真实任务积压、来源失败与恢复；网页打开不等于全流程完成",
        "documentation": f"已登记 {len(files)} 份材料；以每份材料自身版本与时间为准",
    }
    criteria = [{"id": key, "title": title, "weight": weight, "target": target, "view": view,
                 "observed": descriptions[key], "status": "pending" if key in {"latency", "enrichment_accuracy", "qa_accuracy"} else "evidence_available",
                 "status_label": "需依据样本验收" if key in {"latency", "enrichment_accuracy", "qa_accuracy"} else "可查看实现与证据"}
                for key, title, weight, target, view in RUBRIC]
    return {"schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(), "criteria": criteria,
            "quality_runs": quality.get("runs", quality) if isinstance(quality, dict) else quality,
            "observation_windows": observations.get("windows", observations) if isinstance(observations, dict) else observations,
            "evidence": files, "runtime": signals, "observer": worker_state(), "competition_passed": None,
            "method": ["先冻结题单、来源摘要、模型和运行版本，完整保留失败与回退，不挑选成功答案。",
                       "按事实、引用支持、条件保留和推理有效性复核；姓名与独立性仅是复核者声明。",
                       "按预先登记的窗口记录原始发布时间与首次采集时间，再用上游清单核对未采集项。",
                       "72小时是本次选择的观察方案，非赛题硬性要求；结束后保留最多24小时迟到核对。",
                       "初赛不要求所有回答5秒内返回；耗时分布作为性能证据展示，不据此自动打分。"]}
