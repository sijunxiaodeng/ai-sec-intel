"""B's compatible collector, reading the standalone local intelligence API.

A can register this alongside NVD/OSV without importing B's overlapping package
names or accessing its SQLite internals. No orchestrator changes are made here.
"""
import json
import os
import urllib.parse
import urllib.request

from models import intelligence_item
from team_change_protocol import validate_page

DEFAULT_TEAM_BASE_URL = "http://127.0.0.1:8765"


def team_base_url(override=""):
    return (override or os.environ.get("TEAM_INTEL_BASE_URL") or DEFAULT_TEAM_BASE_URL).rstrip("/")


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


class IncrementalIntelligenceCollector:
    """Read all valid AI changes; the caller commits records and cursor together.

    No keyword window and no cursor mutation during network collection. A failed
    page therefore replays from the last durable import on the next attempt.
    """
    source = "b_intelligence"

    def __init__(self, base_url=None, timeout=30, max_pages=10000, cursor=None):
        if type(max_pages) is not int or max_pages <= 0:
            raise ValueError("max_pages must be positive")
        self.base_url = team_base_url(base_url or "")
        self.timeout, self.max_pages = timeout, max_pages
        if cursor is None:
            from database.store import get_sync_cursor
            cursor = get_sync_cursor(self.source)
        self.saved_cursor = cursor or {}
        self.pending_cursor = None

    def get(self, path):
        request = urllib.request.Request(self.base_url + path, headers={"User-Agent": "ai-sec-intel-team"})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.load(response)

    def collect(self):
        saved = self.saved_cursor if self.saved_cursor.get("base_url", self.base_url) == self.base_url else {}
        cursor = saved.get("seq", 0)
        epoch, bound = saved.get("epoch"), None
        expected_epoch = None
        events, reset = {}, False
        self.pending_cursor = None
        for _ in range(self.max_pages):
            params = {"kind": "cve", "cursor": cursor, "limit": 100}
            if epoch:
                params["epoch"] = epoch
            if bound is not None:
                params["through"] = bound
            page = validate_page(self.get("/api/team/changes?" + urllib.parse.urlencode(params)),
                                 cursor, expected_epoch, bound)
            if page["reset"] and expected_epoch is not None:
                raise ValueError("B feed reset during pagination; retry")
            reset = reset or page["reset"]
            epoch = expected_epoch = page["epoch"]
            bound, cursor = page["through"], page["next_cursor"]
            for event in page["changes"]:
                identity = event["entity_id"]
                if event["operation"] == "upsert" and event["item"].get("cve_id") != identity:
                    raise ValueError("B change identity differs from its item")
                events[identity] = event
            if not page["has_more"]:
                self.pending_cursor = {"epoch": epoch, "seq": cursor, "base_url": self.base_url, "reset": reset}
                return {"source": self.source, "cursor": self.pending_cursor, "reset": reset,
                        "items": [intelligence_item(event["item"]) for event in events.values() if event["operation"] == "upsert"],
                        "retracted_ids": [identity for identity, event in events.items() if event["operation"] == "retract"]}
        raise RuntimeError("B change feed exceeded max_pages; no partial result returned")

    def commit_cursor(self):
        """Compatibility only: production uses database.store.apply_sync_page."""
        if self.pending_cursor is None:
            raise ValueError("No successful collection to commit")
        from database.store import set_sync_cursor
        set_sync_cursor(self.source, self.pending_cursor)
        self.saved_cursor = dict(self.pending_cursor)
