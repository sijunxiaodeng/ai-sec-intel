import requests

from collectors.base import IntelligenceItem
from collectors.http import _get


class CISAKEVCollector:
    FEED_URL = ('https://www.cisa.gov/sites/default/files/feeds/'
                'known_exploited_vulnerabilities.json')
    # CISA maintains this repository and documents synchronization within minutes.
    MIRROR_URL = ('https://raw.githubusercontent.com/cisagov/kev-data/develop/'
                  'known_exploited_vulnerabilities.json')

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.endpoint_used = None

    def _snapshot(self):
        headers = {'User-Agent': 'AI-Security-Intelligence-System'}
        try:
            response = _get(self.session, self.FEED_URL, headers=headers, timeout=15, retries=2)
            self.endpoint_used = self.FEED_URL
        except requests.RequestException:
            response = _get(self.session, self.MIRROR_URL, headers=headers, timeout=35, retries=2)
            self.endpoint_used = self.MIRROR_URL
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get('vulnerabilities'), list):
            raise ValueError('CISA KEV feed did not return vulnerabilities list')
        rows = data['vulnerabilities']
        count = data.get('count')
        if count is not None and (not isinstance(count, int) or isinstance(count, bool)
                                  or count != len(rows)):
            raise ValueError('CISA KEV feed count mismatch; incomplete snapshot')
        seen_ids = set()
        for row in rows:
            if not isinstance(row, dict) or not row.get('cveID'):
                raise ValueError('Invalid CISA KEV vulnerability payload')
            identifier = str(row['cveID']).upper()
            if identifier in seen_ids:
                raise ValueError('CISA KEV snapshot contains duplicate CVE IDs')
            seen_ids.add(identifier)
        return rows

    def collect_by_cve(self, cve_id):
        identifier = str(cve_id).strip().upper()
        return [self._parse_vulnerability(row) for row in self._snapshot()
                if str(row['cveID']).upper() == identifier]

    def collect(self, limit=None):
        if limit is not None:
            if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
                raise ValueError('limit must be a nonnegative integer or None')
            if limit == 0:
                return []
        return [self._parse_vulnerability(row) for row in self._snapshot()[:limit]]

    def _parse_vulnerability(self, vulnerability):
        cve_id = str(vulnerability['cveID']).upper()
        vendor = vulnerability.get('vendorProject') or ''
        product = vulnerability.get('product') or ''
        return IntelligenceItem(
            source='CISA_KEV', source_id=cve_id, cve_id=cve_id,
            title=vulnerability.get('vulnerabilityName') or f'{vendor} {product} {cve_id}',
            description=vulnerability.get('shortDescription') or '',
            url='https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
            # dateAdded is the KEV catalog addition date, not CVE publication.
            published_at=None, modified_at=None, severity=None,
            ai_relevance_hint=0.0, tags=['known_exploited', 'cisa_kev'],
            raw_data=vulnerability,
        )
