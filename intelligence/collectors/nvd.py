from datetime import datetime, timedelta, timezone

import requests

from collectors.base import IntelligenceItem


class NVDCollector:

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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
        "open webui",
        "machine learning",
        "large language model",
        "artificial intelligence",
        "llm",
    ]

    def __init__(self, api_key=None):
        self.api_key = api_key

    def collect_by_cve(self, cve_id):

        params = {
            "cveId": cve_id
        }

        headers = {}

        if self.api_key:
            headers["apiKey"] = self.api_key

        response = requests.get(
            self.BASE_URL,
            params=params,
            headers=headers,
            timeout=30,
        )

        response.raise_for_status()

        data = response.json()

        items = []

        for vulnerability in data.get("vulnerabilities", []):
            cve = vulnerability.get("cve", {})

            items.append(
                self._parse_cve(cve)
            )

        return items
    def collect(self, days=3, limit=20):

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        params = {
            "pubStartDate": start_time.isoformat(timespec="milliseconds"),
            "pubEndDate": end_time.isoformat(timespec="milliseconds"),
            "resultsPerPage": limit,
        }

        headers = {}

        if self.api_key:
            headers["apiKey"] = self.api_key

        response = requests.get(
            self.BASE_URL,
            params=params,
            headers=headers,
            timeout=30,
        )

        response.raise_for_status()

        data = response.json()

        items = []

        for vulnerability in data.get("vulnerabilities", []):

            cve = vulnerability.get("cve", {})

            item = self._parse_cve(cve)

            items.append(item)

        return items

    def _parse_cve(self, cve):

        cve_id = cve.get("id", "")

        description = self._get_description(cve)

        severity = self._get_severity(cve)

        ai_score, tags = self._check_ai_relevance(
            cve_id + " " + description
        )

        return IntelligenceItem(
            source="NVD",

            source_id=cve_id,
            cve_id=cve_id,

            title=cve_id,
            description=description,

            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",

            published_at=cve.get("published"),
            modified_at=cve.get("lastModified"),

            severity=severity,

            ai_relevance_hint=ai_score,

            tags=tags,

            raw_data=cve,
        )

    def _get_description(self, cve):

        descriptions = cve.get("descriptions", [])

        for desc in descriptions:

            if desc.get("lang") == "en":
                return desc.get("value", "")

        if descriptions:
            return descriptions[0].get("value", "")

        return ""

    def _get_severity(self, cve):

        metrics = cve.get("metrics", {})

        priority = [
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ]

        for metric_name in priority:

            metric_list = metrics.get(metric_name, [])

            if metric_list:

                cvss_data = metric_list[0].get("cvssData", {})

                return cvss_data.get("baseSeverity")

        return None

    def _check_ai_relevance(self, text):

        text = text.lower()

        matched = []

        for keyword in self.AI_KEYWORDS:

            if keyword.lower() in text:
                matched.append(keyword)

        if matched:

            return 1.0, ["ai_candidate"] + matched

        return 0.0, []