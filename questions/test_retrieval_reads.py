"""Single-item read cost and committed-change invalidation regressions."""
import copy
import json
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from database import store
from database.read_cache import ReadViewCache
from rag import retrieve
from rag.evidence import save
from questions.test_main_store import _record


class ReadViewCacheTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'source.sqlite3'
        with closing(sqlite3.connect(self.path)) as con, con:
            con.execute('PRAGMA journal_mode=WAL')
            con.execute('CREATE TABLE data(value TEXT)')
            con.execute("INSERT INTO data VALUES('first')")
        self.cache = ReadViewCache()
        self.addCleanup(self.cache.clear)
        self.builds = 0

    def build(self):
        self.builds += 1
        with closing(sqlite3.connect(self.path)) as con:
            return [{'value': con.execute('SELECT value FROM data').fetchone()[0]}]

    def read(self):
        return self.cache.get((self.path,), self.build)

    def write(self, value):
        with closing(sqlite3.connect(self.path)) as con, con:
            con.execute('UPDATE data SET value=?', (value,))

    def test_cached_views_are_independent_copies(self):
        first = self.read()
        first[0]['value'] = 'transient display mutation'
        self.assertEqual(self.read(), [{'value': 'first'}])
        self.assertEqual(self.builds, 1)

    def test_other_process_wal_commit_invalidates_next_read(self):
        self.read()
        subprocess.run([sys.executable, '-c',
                        'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); '
                        'c.execute("UPDATE data SET value=?",("external",)); c.commit(); c.close()',
                        str(self.path)], check=True, capture_output=True)
        self.assertEqual(self.read(), [{'value': 'external'}])
        self.assertEqual(self.builds, 2)

    def test_rollback_does_not_publish_uncommitted_data(self):
        self.read()
        with closing(sqlite3.connect(self.path)) as con:
            con.execute("UPDATE data SET value='uncommitted'")
            self.assertEqual(self.read(), [{'value': 'first'}])
            con.rollback()
        self.assertEqual(self.read(), [{'value': 'first'}])
        self.assertEqual(self.builds, 1)

    def test_commit_during_build_cannot_cache_old_result_as_new(self):
        def racing_build():
            value = self.build()
            self.write('committed during build')
            return value
        self.cache.get((self.path,), racing_build)
        self.assertEqual(self.read(), [{'value': 'committed during build'}])
        self.assertEqual(self.builds, 2)

    def test_database_paths_do_not_share_their_version_counters(self):
        self.read()
        other = Path(self.temp.name) / 'other.sqlite3'
        with closing(sqlite3.connect(other)) as con, con:
            con.execute('CREATE TABLE data(value TEXT)')
            con.execute("INSERT INTO data VALUES('different')")
        result = self.cache.get((other,), lambda: [{'value': 'different'}])
        self.assertEqual(result, [{'value': 'different'}])
        self.assertEqual(self.read(), [{'value': 'first'}])

    def test_second_database_changes_also_invalidate(self):
        other = Path(self.temp.name) / 'evidence.sqlite3'
        with closing(sqlite3.connect(other)) as con, con:
            con.execute('CREATE TABLE evidence(value TEXT)')
        self.cache.get((self.path, other), self.build)
        with closing(sqlite3.connect(other)) as con, con:
            con.execute("INSERT INTO evidence VALUES('new source')")
        self.cache.get((self.path, other), self.build)
        self.assertEqual(self.builds, 2)

    def test_concurrent_cache_misses_build_once(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            values = list(pool.map(lambda _: self.read(), range(8)))
        self.assertEqual(self.builds, 1)
        self.assertTrue(all(value == [{'value': 'first'}] for value in values))
        self.assertIsNot(values[0], values[1])


class RetrievalReadsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        constants = {key: self.root / name for key, name in {
            'DB_PATH': 'knowledge.sqlite3', 'KB_PATH': 'knowledge.json',
            'SEED_CARDS_PATH': 'seed.json', 'CARDS_PATH': 'cards.json',
            'CARDS_JS_PATH': 'cards.js', 'RUNS_PATH': 'runs.json'}.items()}
        constants['DATA'] = self.root
        bindings = patch.multiple(store, **constants)
        bindings.start()
        self.addCleanup(bindings.stop)
        env = patch.dict(os.environ, {'MAIN_KB_DB_PATH': str(store.DB_PATH), 'MAIN_IMPORT_DEMO_CARDS': '0'})
        env.start()
        self.addCleanup(env.stop)
        self.db = self.root / 'evidence.sqlite3'
        self.row = _record('CVE-2026-12345')
        save(self.row, [], self.db)
        retrieve._VIEW_CACHE.clear()
        self.addCleanup(retrieve._VIEW_CACHE.clear)

    def test_detail_never_loads_the_full_knowledge_or_archive(self):
        store.upsert([self.row, _record('CVE-2026-22222'), _record('CVE-2026-33333')])
        from enrichment.assessment import enrich_view
        with (patch.object(retrieve, 'knowledge_records', side_effect=AssertionError('bulk view')),
             patch.object(store, '_read_records', side_effect=AssertionError('full main scan')),
             patch.object(retrieve, 'load_records', side_effect=AssertionError('full archive scan')),
             patch('enrichment.assessment.enrich_view', wraps=enrich_view) as enrich):
            result = retrieve.get_record('cve-2026-12345', self.db)
        self.assertEqual(result['item']['cve_id'], 'CVE-2026-12345')
        self.assertEqual(len(enrich.call_args.args[0]), 1)

    def test_point_lookup_preserves_archive_references(self):
        stored = copy.deepcopy(self.row)
        stored['references'] = ['https://example.com/main']
        archive = copy.deepcopy(self.row)
        archive['references'] = ['https://example.com/archive']
        archive['item']['references'] = ['https://example.com/extra']
        save(archive, [], self.db)
        store.upsert([stored])
        result = retrieve.get_record(self.row['item']['cve_id'], self.db)
        self.assertEqual(set(result['references']), {
            'https://example.com/main', 'https://example.com/archive', 'https://example.com/extra'})

    def test_archive_only_record_remains_available(self):
        self.assertEqual(retrieve.get_record(self.row['item']['cve_id'], self.db)['item']['cve_id'],
                         self.row['item']['cve_id'])
        self.assertIsNone(retrieve.get_record('CVE-2099-99999', self.db))

    def test_withdrawn_record_and_archive_only_tombstone_stay_hidden(self):
        cve = self.row['item']['cve_id']
        for present in (False, True):
            with self.subTest(main_record_present=present):
                if present:
                    store.upsert([self.row])
                store.retract([cve])
                with patch.object(retrieve, 'load_record', side_effect=AssertionError('must not resurrect archive')):
                    self.assertIsNone(retrieve.get_record(cve, self.db))

    def test_cached_api_view_updates_after_upsert_retraction_and_restore(self):
        cve = self.row['item']['cve_id']
        store.upsert([self.row])
        self.assertEqual(len(retrieve.cached_knowledge_records(self.db)), 1)
        updated = _record(cve, description='Updated source', updated='2026-10-17T00:00:00Z')
        store.upsert([updated])
        self.assertEqual(retrieve.cached_knowledge_records(self.db)[0]['item']['description'], 'Updated source')
        store.retract([cve])
        self.assertEqual(retrieve.cached_knowledge_records(self.db), [])
        store.upsert([updated])
        self.assertEqual(len(retrieve.cached_knowledge_records(self.db)), 1)

    def test_cached_api_view_updates_after_evidence_archive_change(self):
        first = retrieve.cached_knowledge_records(self.db)
        archive = copy.deepcopy(self.row)
        archive['item']['description'] = 'New archive revision'
        save(archive, [], self.db)
        second = retrieve.cached_knowledge_records(self.db)
        self.assertEqual(first[0]['item']['description'], 'Original facts')
        self.assertEqual(second[0]['item']['description'], 'New archive revision')

    def test_task_status_commits_do_not_rebuild_content_view(self):
        store.upsert([self.row])
        with closing(store._connect()) as con:
            con.execute('CREATE TABLE task_heartbeat(value INTEGER)')
        retrieve.cached_knowledge_records(self.db)
        with closing(store._connect()) as con:
            con.execute('INSERT INTO task_heartbeat VALUES(1)')
        with patch.object(retrieve, 'knowledge_records', side_effect=AssertionError('unrelated task invalidation')):
            self.assertEqual(len(retrieve.cached_knowledge_records(self.db)), 1)

    def test_direct_sql_payload_update_also_invalidates_content_view(self):
        store.upsert([self.row])
        retrieve.cached_knowledge_records(self.db)
        cve = self.row['item']['cve_id']
        with closing(sqlite3.connect(store.database_path())) as con, con:
            row = json.loads(con.execute('SELECT payload_json FROM knowledge_records WHERE cve_id=?', (cve,)).fetchone()[0])
            row['item']['description'] = 'Direct external correction'
            # Deliberately leave updated_at and knowledge_revisions untouched.
            con.execute('UPDATE knowledge_records SET payload_json=? WHERE cve_id=?', (json.dumps(row), cve))
        self.assertEqual(retrieve.cached_knowledge_records(self.db)[0]['item']['description'], 'Direct external correction')


if __name__ == '__main__':
    unittest.main()
