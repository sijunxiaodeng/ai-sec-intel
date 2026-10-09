from datetime import datetime, timedelta, timezone
import os
import re
import time

import requests

from collectors.http import _get, nvd_page
from incremental.api_collectors import _api_timestamp, _nvd_description, _nvd_severity, from_nvd


class NVDCollector:
    BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    AI_KEYWORDS = [
        'ollama', 'vllm', 'triton', 'pytorch', 'tensorflow', 'huggingface',
        'transformers', 'langchain', 'llamaindex', 'gradio', 'open webui',
        'machine learning', 'large language model', 'artificial intelligence', 'llm',
    ]

    def __init__(self, api_key=None, session=None, max_pages=30):
        self.api_key = api_key if api_key is not None else os.getenv('NVD_API_KEY', '')
        self.session = session or requests.Session()
        if max_pages <= 0:
            raise ValueError('max_pages must be positive')
        self.max_pages = max_pages
        self._last_call = None

    def _rate_limit(self):
        interval = 0.8 if self.api_key else 6.5
        if self._last_call is not None:
            pause = interval - (time.monotonic() - self._last_call)
            if pause > 0:
                time.sleep(pause)
        self._last_call = time.monotonic()

    def _collect_pages(self, params, limit=None):
        headers = {'User-Agent': 'AI-Security-Intelligence-System'}
        if self.api_key:
            headers['apiKey'] = self.api_key
        params = {**params, 'resultsPerPage': min(limit or 2000, 2000)}
        items, seen_ids = [], set()
        start_index, total = 0, None
        for _ in range(self.max_pages):
            response = _get(self.session, self.BASE_URL, headers=headers,
                            params={**params, 'startIndex': start_index},
                            before_request=self._rate_limit)
            rows, total = nvd_page(response.json(), start_index, total)
            for row in rows:
                raw = row.get('cve') if isinstance(row, dict) else None
                if not isinstance(raw, dict) or not raw.get('id'):
                    raise ValueError('Invalid NVD CVE payload')
                if raw['id'] in seen_ids:
                    raise RuntimeError('NVD repeated CVE during pagination; retry later')
                seen_ids.add(raw['id'])
                items.append(self._parse_cve(raw))
            start_index += len(rows)
            if start_index >= total or (limit is not None and len(items) >= limit):
                return items[:limit] if limit is not None else items
        raise RuntimeError(f'NVD reached max_pages={self.max_pages}; result is incomplete')

    def collect_by_cve(self, cve_id):
        return self._collect_pages({'cveId': str(cve_id).strip().upper()})

    def collect(self, days=3, limit=20):
        if days < 0 or days > 119:
            raise ValueError('days must be between 0 and 119')
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise ValueError('limit must be a nonnegative integer')
        if not days or not limit:
            return []
        end_time = datetime.now(timezone.utc)
        return self._collect_pages({
            'pubStartDate': _api_timestamp(end_time - timedelta(days=days)),
            'pubEndDate': _api_timestamp(end_time),
        }, limit=limit)

    def _parse_cve(self, cve):
        item = from_nvd(cve)
        item.ai_relevance_hint, item.tags = self._check_ai_relevance(
            item.cve_id + ' ' + item.description)
        return item

    def _get_description(self, cve):
        return _nvd_description(cve)

    def _get_severity(self, cve):
        return _nvd_severity(cve)

    def _check_ai_relevance(self, text):
        matched = [term for term in self.AI_KEYWORDS
                   if re.search(r'(?<!\w)' + re.escape(term) + r'(?!\w)', text, re.I)]
        return (1.0, ['ai_candidate', *matched]) if matched else (0.0, [])
