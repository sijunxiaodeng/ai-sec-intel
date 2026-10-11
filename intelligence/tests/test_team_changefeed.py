"""Real SQLite transactions and stable team-feed pagination, no network."""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ai_pipeline.store import ClassificationStore
from ai_pipeline.documents import DocumentClassificationStore
from api_v6.change_repository import ChangeRepository
from api_v6.repository import IntelligenceRepository
from collectors.base import IntelligenceItem
from collectors.documents import KnowledgeDocument, document_id
from storage.changefeed import ensure_changefeed
from storage.sqlite_store import SQLiteIntelligenceStore
from storage.document_store import SQLiteDocumentStore


def item(number=0, description="Ollama vulnerability"):
    cve = f"CVE-2026-{10000 + number}"
    return IntelligenceItem(source="NVD", source_id=cve, cve_id=cve, title=cve,
        description=description, url=f"https://nvd.nist.gov/vuln/detail/{cve}",
        published_at="2026-10-08T00:00:00Z", modified_at=None, severity=None, raw_data={"id": cve})


def result(positive=True):
    return SimpleNamespace(is_ai_related=positive, category="ai_infrastructure", confidence=0.95,
        reason="Fixture ground truth", evidence=["Ollama"], decision_source="rule",
        needs_review=False, rule_score=0.95)


class TeamChangefeedTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.db = self.root / "intelligence.db"
        self.store = SQLiteIntelligenceStore(self.db)
        self.classification = ClassificationStore(self.db)
        # Be explicit in this test so it also covers stores created before the
        # classification-schema upgrade has run.
        with self.classification.connect() as connection:
            ensure_changefeed(connection)
        self.feed = ChangeRepository(IntelligenceRepository(self.db, self.root))
        mocked = patch("api_v6.change_repository.current_classifier_version", return_value="v-test")
        mocked.start()
        self.addCleanup(mocked.stop)

    def add(self, count=1):
        self.store.ingest_batch("NVD", [item(number) for number in range(count)])
        for row in self.classification.fresh("v-test", count + 10):
            self.classification.record(row, "v-test", "classified", result=result())

    def drain(self, cursor=0, epoch=None):
        events, through = [], None
        while True:
            page = self.feed.page(kind="cve", cursor=cursor, epoch=epoch, through=through, limit=37)
            events.extend(page["changes"])
            epoch, cursor, through = page["epoch"], page["next_cursor"], page["through"]
            if not page["has_more"]:
                return events, cursor, epoch

    def test_initial_snapshot_more_than_200_and_old_record_update(self):
        self.add(251)
        events, cursor, epoch = self.drain()
        self.assertEqual(len(events), 251)
        self.assertEqual({row["operation"] for row in events}, {"upsert"})
        self.store.ingest_batch("NVD", [item(0, "Corrected Ollama affected version")])
        stale = self.feed.page(kind="cve", cursor=cursor, epoch=epoch)
        self.assertEqual(stale["changes"][0]["operation"], "retract")
        row = self.classification.fresh("v-test", 1)[0]
        self.classification.record(row, "v-test", "classified", result=result())
        changed, _, _ = self.drain(cursor, epoch)
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["item"]["description"], "Corrected Ollama affected version")

    def test_positive_to_negative_is_an_explicit_retraction(self):
        self.add()
        events, cursor, epoch = self.drain()
        row = {"cve_id": events[0]["entity_id"]}
        with closing(sqlite3.connect(self.db)) as connection:
            row["content_sha256"] = connection.execute("SELECT content_sha256 FROM unified_vulnerabilities").fetchone()[0]
        self.classification.record(row, "v-test", "classified", result=result(False))
        changed, _, _ = self.drain(cursor, epoch)
        self.assertEqual([(e["entity_id"], e["operation"]) for e in changed], [(row["cve_id"], "retract")])

    def test_new_writes_do_not_shift_a_fixed_page_boundary(self):
        self.add(101)
        first = self.feed.page(kind="cve", limit=50)
        self.store.ingest_batch("NVD", [item(500)])
        row = self.classification.fresh("v-test", 1)[0]
        self.classification.record(row, "v-test", "classified", result=result())
        second = self.feed.page(kind="cve", cursor=first["next_cursor"], epoch=first["epoch"], through=first["through"], limit=100)
        self.assertEqual(len(first["changes"]) + len(second["changes"]), 101)
        after = self.feed.page(kind="cve", cursor=second["next_cursor"], epoch=second["epoch"])
        self.assertEqual([event["entity_id"] for event in after["changes"]], ["CVE-2026-10500"])

    def test_failed_transaction_cannot_publish_a_change(self):
        self.add()
        _, cursor, epoch = self.drain()
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("UPDATE ai_classifications SET ai_related=0")
            connection.rollback()
        finally:
            connection.close()
        page = self.feed.page(kind="cve", cursor=cursor, epoch=epoch)
        self.assertEqual(page["changes"], [])
        self.assertEqual(page["next_cursor"], cursor)

    def test_document_feed_requires_current_positive_verdict_and_withdraws_changes(self):
        documents = SQLiteDocumentStore(self.db)
        document = KnowledgeDocument(document_id("BLOG", "one"), "BLOG", "security_blog", "blog",
            "Artificial Intelligence Privacy Standard", "Privacy safeguards",
            "https://example.org/published", "2026-10-01T00:00:00Z", None,
            raw_data={"source_text": "Original privacy safeguards"})
        documents.ingest("BLOG", "security_blog", [document])
        pending = self.feed.page(kind="document")
        self.assertEqual(pending["changes"][0]["operation"], "retract")
        classification = DocumentClassificationStore(self.db)
        row = classification.fresh("v-test", 1)[0]
        classification.record(row, "v-test", result())
        approved = self.feed.page(kind="document", cursor=pending["next_cursor"], epoch=pending["epoch"])
        self.assertEqual(approved["changes"][0]["operation"], "upsert")
        payload = approved["changes"][0]["item"]
        self.assertNotIn("raw_data", payload)
        self.assertEqual(payload["classification"]["classifier_version"], "v-test")
        document.description = "Updated source description"
        documents.ingest("BLOG", "security_blog", [document])
        stale = self.feed.page(kind="document", cursor=approved["next_cursor"], epoch=approved["epoch"])
        self.assertEqual(stale["changes"][0]["operation"], "retract")
        row = classification.fresh("v-test", 1)[0]
        classification.record(row, "v-test", result(False))
        negative = self.feed.page(kind="document", cursor=stale["next_cursor"], epoch=stale["epoch"])
        self.assertEqual(negative["changes"][0]["operation"], "retract")

    def test_migration_backfills_all_and_reinitialization_is_idempotent(self):
        self.add(251)
        with closing(sqlite3.connect(self.db)) as connection, connection:
            triggers = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")]
            for name in triggers:
                connection.execute(f"DROP TRIGGER {name}")
            connection.execute("DROP TABLE team_changes")
            connection.execute("DROP TABLE team_feed_meta")
        SQLiteIntelligenceStore(self.db)
        events, cursor, _ = self.drain()
        self.assertEqual(len(events), 251)
        SQLiteIntelligenceStore(self.db)
        self.assertEqual(self.feed.page(kind="cve")["through"], cursor)

    def test_atomic_mirror_link_swap_is_visible_without_api_restart(self):
        self.add()
        link = self.root / "current"
        os.symlink(self.root, link, target_is_directory=True)
        feed = ChangeRepository(IntelligenceRepository(link / "intelligence.db", self.root))
        original = feed.page(kind="cve")
        replacement = self.root / "next"
        replacement.mkdir()
        SQLiteIntelligenceStore(replacement / "intelligence.db")
        fresh_link = self.root / "current.next"
        os.symlink(replacement, fresh_link, target_is_directory=True)
        os.replace(fresh_link, link)
        changed = feed.page(kind="cve", cursor=original["next_cursor"], epoch=original["epoch"])
        self.assertTrue(changed["reset"])
        self.assertNotEqual(changed["epoch"], original["epoch"])
        self.assertEqual(changed["changes"], [])


if __name__ == "__main__":
    unittest.main()
