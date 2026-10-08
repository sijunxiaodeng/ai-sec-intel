from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class UnifiedVulnerability:

    # =========================
    # 基础标识
    # =========================

    cve_id: str

    title: str = ""
    description: str = ""

    # =========================
    # 风险信息
    # =========================

    severity: Optional[str] = None

    cvss_score: Optional[float] = None

    epss_score: Optional[float] = None

    cwes: list[str] = field(default_factory=list)

    # =========================
    # 厂商 / 产品
    # =========================

    vendor: Optional[str] = None
    product: Optional[str] = None

    # =========================
    # CISA KEV
    # =========================

    known_exploited: bool = False

    kev_date_added: Optional[str] = None

    required_action: Optional[str] = None

    # =========================
    # GitHub Advisory
    # =========================

    ghsa_ids: list[str] = field(default_factory=list)

    affected_packages: list[dict] = field(
        default_factory=list
    )

    # =========================
    # 时间
    # =========================

    published_at: Optional[str] = None

    modified_at: Optional[str] = None

    # =========================
    # AI 相关性
    # =========================

    ai_relevance_hint: float = 0.0
    ai_related: bool = False

    ai_category: str = "unknown"

    ai_evidence: list[str] = field(
        default_factory=list
    )

    # =========================
    # 来源 / 标签 / 引用
    # =========================

    sources: list[str] = field(default_factory=list)

    tags: list[str] = field(default_factory=list)

    references: list[str] = field(default_factory=list)

    # =========================
    # 保存各来源原始数据
    # =========================

    raw_by_source: dict[str, Any] = field(
        default_factory=dict
    )