"""Routing from archived CPE bytes when the main product field is missing."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from enrichment.asset_candidates import archived_identities
from enrichment.documents import digest


class ArchivedAssetCandidatesTest(unittest.TestCase):
    def test_exact_archived_identity_routes_and_changed_digest_is_rechecked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sources.sqlite3"
            cv = "CVE-2024-37032"
            sid = digest("https://nvd.nist.gov/vuln/detail/" + cv)[:16]
            body = json.dumps({"vulnerabilities": [{"cve": {"id": cv, "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*"}]}]}]}}]}).encode()
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.execute("CREATE TABLE source_snapshots(cve_id,source_id,digest,body)")
                conn.execute("INSERT INTO source_snapshots VALUES(?,?,?,?)", (cv,sid,hashlib.sha256(body).hexdigest(),body))
            self.assertEqual(archived_identities([cv],evidence_db=path)[cv], {("a","ollama","ollama")})
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.execute("UPDATE source_snapshots SET digest=?", ("0" * 64,))
            self.assertEqual(archived_identities([cv],evidence_db=path), {})

    def test_wrong_cve_or_non_nvd_source_cannot_supply_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sources.sqlite3"
            cv = "CVE-2024-37032"
            body = b'{"vulnerabilities":[{"cve":{"id":"CVE-2099-10000"}}]}'
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.execute("CREATE TABLE source_snapshots(cve_id,source_id,digest,body)")
                conn.execute("INSERT INTO source_snapshots VALUES(?,?,?,?)", (cv,digest("https://nvd.nist.gov/vuln/detail/"+cv)[:16],hashlib.sha256(body).hexdigest(),body))
            self.assertEqual(archived_identities([cv],evidence_db=path), {})
