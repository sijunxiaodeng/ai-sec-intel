"""Read B team intelligence — in-process by default (unified app), HTTP sidecar optional."""
import json
import os
import urllib.parse
import urllib.request

from models import intelligence_item

DEFAULT_TEAM_BASE_URL = "http://127.0.0.1:8765"


def team_intel_mode():
    return os.environ.get("TEAM_INTEL_MODE", "embed").strip().lower()


def team_base_url(override=""):
    """HTTP base when TEAM_INTEL_MODE=sidecar. Unused for embed collectors."""
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
        mode = team_intel_mode()
        if mode in {"embed", "inprocess", "1", "true", "yes", ""}:
            return self._collect_embed()
        return self._collect_http()

    def _collect_embed(self):
        from api.b_embed import list_team_page

        items, offset = [], 0
        for _ in range(self.max_pages):
            page = list_team_page(self.keyword, limit=100, offset=offset, ai_only=True)
            rows = page.get("items")
            total = page.get("total")
            if not isinstance(rows, list) or type(total) is not int or total < 0:
                raise ValueError("B in-process team list returned invalid pagination")
            for row in rows:
                if not isinstance(row, dict) or not row.get("cve_id"):
                    raise ValueError("B in-process team list returned an invalid IntelligenceItem")
                items.append(intelligence_item(row))
            offset += len(rows)
            if offset >= total:
                return items
            if not rows:
                raise ValueError("B in-process pagination stopped before total records")
        raise RuntimeError("B in-process pagination exceeded max_pages; no partial result returned")

    def _collect_http(self):
        items, offset = [], 0
        for _ in range(self.max_pages):
            query = urllib.parse.urlencode({
                "q": self.keyword, "ai_only": "true", "limit": 100, "offset": offset,
            })
            request = urllib.request.Request(
                self.base_url + "/api/intelligence/team?" + query,
                headers={"User-Agent": "ai-sec-intel-team"},
            )
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
