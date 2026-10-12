"""OSV package advisories collected by the single B pipeline.

Query every configured package/page before committing the batch. There is no
keyword-to-GitHub guess and no watermark that can skip truncated results.
"""
import re
from urllib.parse import quote

import requests

from collectors.base import IntelligenceItem
from collectors.documents import KnowledgeDocument, make_document_id


class OSVCollector:
    QUERY_URL = "https://api.osv.dev/v1/query"
    DEFAULT_PACKAGES = ("vllm", "transformers", "langchain", "ollama", "torch", "tensorflow")

    def __init__(self, *, session=None, packages=None, max_pages=100):
        self.session = session or requests.Session()
        self.packages = tuple(packages or self.DEFAULT_PACKAGES)
        if not self.packages or any(not isinstance(p, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in self.packages):
            raise ValueError("OSV packages must be explicit PyPI package names")
        if type(max_pages) is not int or max_pages < 1:
            raise ValueError("max_pages must be positive")
        self.max_pages = max_pages

    def collect(self):
        found = {}
        for name in self.packages:
            token, tokens = None, set()
            for _ in range(self.max_pages):
                body = {"package": {"ecosystem": "PyPI", "name": name}}
                if token:
                    body["page_token"] = token
                response = self.session.post(self.QUERY_URL, json=body, timeout=30)
                try:
                    response.raise_for_status()
                    payload = response.json()
                finally:
                    response.close()
                if not isinstance(payload, dict) or not isinstance(payload.get("vulns", []), list):
                    raise ValueError("Invalid OSV query response")
                for row in payload.get("vulns", []):
                    for item in self.parse(row):
                        previous = found.get(item.source_id)
                        if previous is None or (item.modified_at or "") >= (previous.modified_at or ""):
                            found[item.source_id] = item
                token = payload.get("next_page_token")
                if token is None or token == "":
                    break
                if not isinstance(token, str) or token in tokens:
                    raise ValueError("OSV pagination token is invalid or repeated")
                tokens.add(token)
            else:
                raise RuntimeError("Incomplete OSV pagination; retry the whole source")
        return list(found.values())

    @staticmethod
    def documents(items):
        """Keep advisory identities queryable even before a CVE is assigned."""
        found = {}
        for item in items:
            raw = item.raw_data
            identity = raw['id']
            if identity not in found:
                found[identity] = KnowledgeDocument(
                    document_id=make_document_id('OSV', identity), source='OSV',
                    source_category='vulnerability_database', content_type='vendor_advisory',
                    title=item.title, description=item.description, url=item.url,
                    published_at=item.published_at, modified_at=item.modified_at,
                    raw_data={'advisory': raw},
                )
            if item.cve_id and item.cve_id not in found[identity].cve_ids:
                found[identity].cve_ids.append(item.cve_id)
        return list(found.values())

    @staticmethod
    def parse(row):
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
            raise ValueError("OSV advisory identity missing")
        if row.get("withdrawn"):
            # Never import a withdrawn advisory as an active vulnerability.
            # Persist this source failure for review instead of returning success.
            raise ValueError("OSV returned a withdrawn advisory; source review required")
        aliases = row.get("aliases", [])
        if not isinstance(aliases, list):
            raise ValueError("OSV aliases must be a list")
        cves = sorted({value for value in [row["id"], *aliases]
                       if isinstance(value, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", value)})
        return [IntelligenceItem(
            source="OSV", source_id=row["id"] + (":" + cve if cve else ""), cve_id=cve,
            title=row.get("summary") or row["id"], description=row.get("details") or row.get("summary") or "",
            url="https://osv.dev/vulnerability/" + quote(row["id"], safe=""),
            published_at=row.get("published"), modified_at=row.get("modified"),
            severity=None, raw_data=row,
        ) for cve in (cves or [None])]
