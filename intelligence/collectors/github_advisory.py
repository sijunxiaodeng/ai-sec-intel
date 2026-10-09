import os
import re

import requests
from dotenv import load_dotenv

from collectors.http import _get, github_next_url
from incremental.api_collectors import from_github


load_dotenv()


class GitHubAdvisoryCollector:
    BASE_URL = 'https://api.github.com/advisories'
    AI_KEYWORDS = [
        'ollama', 'vllm', 'triton', 'pytorch', 'tensorflow', 'huggingface',
        'transformers', 'langchain', 'llamaindex', 'gradio', 'weaviate',
        'milvus', 'qdrant', 'chroma', 'open webui', 'machine learning',
        'large language model', 'artificial intelligence', 'llm', 'embedding',
        'vector database',
    ]

    def __init__(self, token=None, session=None, max_pages=30):
        self.token = token if token is not None else (os.getenv('GITHUB_TOKEN') or os.getenv('GH_TOKEN'))
        self.session = session or requests.Session()
        if max_pages <= 0:
            raise ValueError('max_pages must be positive')
        self.max_pages = max_pages

    def _collect_pages(self, params, limit=None):
        headers = {
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'AI-Security-Intelligence-System',
        }
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        url, seen_urls, seen_ids, items = self.BASE_URL, set(), set(), []
        for _ in range(self.max_pages):
            if url in seen_urls:
                raise RuntimeError('GitHub pagination loop')
            seen_urls.add(url)
            response = _get(self.session, url, headers=headers, params=params)
            advisories = response.json()
            if not isinstance(advisories, list):
                raise ValueError('GitHub advisories API did not return a list')
            for advisory in advisories:
                if not isinstance(advisory, dict) or not advisory.get('ghsa_id'):
                    raise ValueError('Invalid GitHub advisory payload')
                if advisory['ghsa_id'] in seen_ids:
                    raise RuntimeError('GitHub repeated advisory during pagination; retry later')
                seen_ids.add(advisory['ghsa_id'])
                items.append(self._parse_advisory(advisory))
            url = github_next_url(response)
            if not url or (limit is not None and len(items) >= limit):
                return items[:limit] if limit is not None else items
            if not advisories:
                raise RuntimeError('GitHub returned empty page before final page')
            params = None
        raise RuntimeError(f'GitHub reached max_pages={self.max_pages}; result is incomplete')

    def collect(self, limit=20, severity=None, ecosystem=None):
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise ValueError('limit must be a nonnegative integer')
        if not limit:
            return []
        params = {'type': 'reviewed', 'per_page': min(limit, 100),
                  'sort': 'published', 'direction': 'desc'}
        if severity:
            params['severity'] = severity
        if ecosystem:
            params['ecosystem'] = ecosystem
        return self._collect_pages(params, limit=limit)

    def collect_by_cve(self, cve_id):
        return self._collect_pages({'cve_id': str(cve_id).strip().upper(), 'per_page': 100})

    def _parse_advisory(self, advisory):
        item = from_github(advisory)
        score, tags = self._check_ai_relevance(' '.join([
            item.title, item.description, self._package_text(advisory),
        ]))
        item.ai_relevance_hint = score
        item.tags = ['github_advisory', 'ghsa', *tags]
        return item

    def _package_text(self, advisory):
        names = []
        for vulnerability in advisory.get('vulnerabilities') or []:
            package = vulnerability.get('package') or {}
            names.append(f"{package.get('ecosystem', '')} {package.get('name', '')}")
        return ' '.join(names)

    def _check_ai_relevance(self, text):
        matched = [term for term in self.AI_KEYWORDS
                   if re.search(r'(?<!\w)' + re.escape(term) + r'(?!\w)', text, re.I)]
        return (1.0, ['ai_candidate', *matched]) if matched else (0.0, [])
