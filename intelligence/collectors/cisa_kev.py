import requests

from collectors.base import IntelligenceItem


class CISAKEVCollector:

    FEED_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    def collect_by_cve(self, cve_id):

        response = requests.get(
            self.FEED_URL,
            timeout=30,
            headers={
                "User-Agent":
                    "Mozilla/5.0 "
                    "AI-Security-Intelligence-System"
            }
        )

        response.raise_for_status()

        data = response.json()

        results = []

        for vulnerability in data.get(
                "vulnerabilities",
                []
        ):

            if (
                    vulnerability.get("cveID")
                    == cve_id
            ):
                results.append(
                    self._parse_vulnerability(
                        vulnerability
                    )
                )

        return results
    def collect(self, limit=None):

        response = requests.get(
            self.FEED_URL,
            timeout=30,
            headers={
                "User-Agent": "Mozilla/5.0 AI-Security-Intelligence-System"
            }
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])

        if limit is not None:
            vulnerabilities = vulnerabilities[:limit]

        items = []

        for vulnerability in vulnerabilities:

            item = self._parse_vulnerability(vulnerability)

            items.append(item)

        return items

    def _parse_vulnerability(self, vulnerability):

        cve_id = vulnerability.get("cveID", "")

        vendor = vulnerability.get("vendorProject", "")
        product = vulnerability.get("product", "")
        vulnerability_name = vulnerability.get(
            "vulnerabilityName",
            ""
        )

        short_description = vulnerability.get(
            "shortDescription",
            ""
        )

        required_action = vulnerability.get(
            "requiredAction",
            ""
        )

        title = vulnerability_name

        if not title:
            title = f"{vendor} {product} {cve_id}"

        tags = [
            "known_exploited",
            "cisa_kev"
        ]

        return IntelligenceItem(

            source="CISA_KEV",

            source_id=cve_id,
            cve_id=cve_id,

            title=title,

            description=short_description,

            url=(
                "https://www.cisa.gov/"
                "known-exploited-vulnerabilities-catalog"
            ),

            published_at=vulnerability.get(
                "dateAdded"
            ),

            modified_at=None,

            severity=None,

            ai_relevance_hint=0.0,

            tags=tags,

            raw_data={
                **vulnerability,

                "vendor": vendor,
                "product": product,
                "required_action": required_action,
            }
        )