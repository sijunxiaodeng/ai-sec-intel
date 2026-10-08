import os
import requests

from dotenv import load_dotenv

from collectors.base import IntelligenceItem


load_dotenv()


class GitHubAdvisoryCollector:

    BASE_URL = "https://api.github.com/advisories"

    AI_KEYWORDS = [
        "ollama",
        "vllm",
        "triton",
        "pytorch",
        "tensorflow",
        "huggingface",
        "transformers",
        "langchain",
        "llamaindex",
        "gradio",
        "weaviate",
        "milvus",
        "qdrant",
        "chroma",
        "open webui",
        "machine learning",
        "large language model",
        "artificial intelligence",
        "llm",
        "embedding",
        "vector database",
    ]

    def __init__(self, token=None):

        self.token = token or os.getenv("GITHUB_TOKEN")

        if not self.token:
            print(
                "警告：未检测到 GITHUB_TOKEN，"
                "将使用 GitHub 未认证 API，容易触发限流。"
            )

    def collect(self, limit=20, severity=None, ecosystem=None):

        params = {
            "per_page": min(limit, 100),
            "sort": "published",
            "direction": "desc",
        }

        if severity:
            params["severity"] = severity

        if ecosystem:
            params["ecosystem"] = ecosystem

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "AI-Security-Intelligence-System",
        }

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        response = requests.get(
            self.BASE_URL,
            params=params,
            headers=headers,
            timeout=30,
        )

        if response.status_code == 403:
            remaining = response.headers.get(
                "X-RateLimit-Remaining"
            )

            reset_time = response.headers.get(
                "X-RateLimit-Reset"
            )

            raise RuntimeError(
                "GitHub API 请求被限流。"
                f" Remaining={remaining},"
                f" Reset={reset_time}。"
                " 请检查 GITHUB_TOKEN 是否配置正确。"
            )

        response.raise_for_status()

        advisories = response.json()

        items = []

        for advisory in advisories[:limit]:

            item = self._parse_advisory(advisory)

            items.append(item)

        return items

    def collect_by_cve(self, cve_id):

        params = {
            "cve_id": cve_id
        }

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "AI-Security-Intelligence-System",
        }

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        response = requests.get(
            self.BASE_URL,
            params=params,
            headers=headers,
            timeout=30,
        )

        response.raise_for_status()

        advisories = response.json()

        return [
            self._parse_advisory(advisory)
            for advisory in advisories
        ]

    def _parse_advisory(self, advisory):

        ghsa_id = advisory.get("ghsa_id", "")
        cve_id = advisory.get("cve_id")

        summary = advisory.get("summary", "")
        description = advisory.get("description", "")

        severity = advisory.get("severity")

        ai_score, ai_tags = self._check_ai_relevance(
            " ".join([
                summary or "",
                description or "",
                self._package_text(advisory),
            ])
        )

        tags = [
            "github_advisory",
            "ghsa",
            *ai_tags
        ]

        return IntelligenceItem(
            source="GITHUB_ADVISORY",

            source_id=ghsa_id,
            cve_id=cve_id,

            title=summary or ghsa_id,
            description=description,

            url=advisory.get("html_url"),

            published_at=advisory.get("published_at"),
            modified_at=advisory.get("updated_at"),

            severity=(
                severity.upper()
                if severity
                else None
            ),

            ai_relevance_hint=ai_score,

            tags=tags,

            raw_data=advisory,
        )

    def _package_text(self, advisory):

        names = []

        for vulnerability in advisory.get(
            "vulnerabilities",
            []
        ):

            package = vulnerability.get(
                "package",
                {}
            )

            name = package.get("name", "")
            ecosystem = package.get("ecosystem", "")

            names.append(
                f"{ecosystem} {name}"
            )

        return " ".join(names)

    def _check_ai_relevance(self, text):

        text = text.lower()

        matched = []

        for keyword in self.AI_KEYWORDS:

            if keyword.lower() in text:
                matched.append(keyword)

        if matched:
            return 1.0, [
                "ai_candidate",
                *matched
            ]

        return 0.0, []