"""B's compatible collector, reading the standalone local intelligence API.

A can register this alongside NVD/OSV without importing B's overlapping package
names or accessing its SQLite internals. No orchestrator changes are made here.
"""
import json
import os
import urllib.parse
import urllib.request

from models import intelligence_item

DEFAULT_TEAM_BASE_URL = "http://127.0.0.1:8765"


def team_base_url(override=""):
    """Server-side B base URL.

    Prefer TEAM_INTEL_UPSTREAM (localhost :8765) so collectors never HTTP-loop
    through the :8023 reverse proxy (single-worker deadlock). TEAM_INTEL_BASE_URL
    remains a legacy alias when UPSTREAM is unset.
    """
    return (
        override
        or os.environ.get("TEAM_INTEL_UPSTREAM")
        or os.environ.get("TEAM_INTEL_BASE_URL")
        or DEFAULT_TEAM_BASE_URL
    ).rstrip("/")


class IntelligenceCollector:
    def __init__(self, keyword="", base_url=None, timeout=30, max_pages=100):
        if max_pages <= 0:
            raise ValueError("max_pages must be positive")
        self.keyword = keyword
        self.base_url = team_base_url(base_url or "")
        self.timeout = timeout
        self.max_pages = max_pages

    def collect(self):
        items, offset = [], 0
        for _ in range(self.max_pages):
            query = urllib.parse.urlencode({"q": self.keyword, "ai_only": "true", "limit": 100, "offset": offset})
            request = urllib.request.Request(self.base_url + "/api/intelligence/team?" + query,
                                             headers={"User-Agent": "ai-sec-intel-team"})
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                page = json.load(response)
            rows = page.get("items")
            total = page.get("total")
            if not isinstance(rows, list) or type(total) is not int or total < 0:
                raise ValueError("B API returned invalid pagination")
            for row in rows:
                if not isinstance(row, dict) or not row.get("cve_id"):
                    raise ValueError("B API returned an invalid IntelligenceItem")
                items.append(intelligence_item(row))
            offset += len(rows)
            if offset >= total:
                return items
            if not rows:
                raise ValueError("B API pagination stopped before total records")
        raise RuntimeError("B API pagination exceeded max_pages; no partial result returned")
