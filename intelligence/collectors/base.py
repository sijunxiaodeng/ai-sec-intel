from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class IntelligenceItem:
    source: str

    source_id: str
    cve_id: Optional[str]

    title: str
    description: str

    url: Optional[str]

    published_at: Optional[str]
    modified_at: Optional[str]

    severity: Optional[str]

    ai_relevance_hint: Optional[float] = None

    tags: list[str] = field(default_factory=list)

    raw_data: dict[str, Any] = field(default_factory=dict)