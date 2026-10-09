"""Offline tests exercise durable history, lost snapshots and credential isolation."""
import io
import json
import sqlite3
import tempfile
import unittest
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import patch

from deployment.actions_state import (
    ARTIFACT_PREFIX, BOOTSTRAP_ASSET, GitHubClient, SafeRedirect, StateError, prune_states, restore_archive, restore_latest, save_state,
)

REPOSITORY = 'team/public-repo'
BRANCH = 'main'
FIRST_SEEN = '2026-10-08T01:02:03.123456+00:00'
BASELINE = '2026-10-07T00:00:00+00:00'


def fixture(directory):
    directory.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(directory / 'intelligence.db')
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript('''
        CREATE TABLE source_items(source_id TEXT, first_seen_at TEXT);
        CREATE TABLE unified_vulnerabilities(cve_id TEXT, first_seen_at TEXT);
        CREATE TABLE source_observation_baselines(source TEXT, started_at TEXT);
        CREATE TABLE incremental_cursors(source TEXT, cursor TEXT);
        CREATE TABLE document_http_state(source TEXT, etag TEXT);
        CREATE TABLE ai_classifications(cve_id TEXT, state TEXT);
    ''')
    db.execute('INSERT INTO source_items VALUES (?,?)', ('GHSA-1234', FIRST_SEEN))
    db.execute('INSERT INTO unified_vulnerabilities VALUES (?,?)', ('CVE-2026-10001', FIRST_SEEN))
    db.execute('INSERT INTO source_observation_baselines VALUES (?,?)', ('NVD', BASELINE))
    db.execute('INSERT INTO incremental_cursors VALUES (?,?)', ('NVD', FIRST_SEEN))
    db.execute('INSERT INTO document_http_state VALUES (?,?)', ('BLOG', 'etag-original'))
    db.execute('INSERT INTO ai_classifications VALUES (?,?)', ('CVE-2026-10001', 'classified'))
    db.commit()
    # Keep the connection open: online backup must include committed WAL pages.
    (directory / 'monitoring_baseline.json').write_text(json.dumps({'started_at': BASELINE}))
    (directory / 'monitoring_status.json').write_text(json.dumps({'status': 'partial'}))
    (directory / 'classification_status.json').write_text(json.dumps({'status': 'success'}))
    (directory / '.env').write_text('LLM_API_KEY=fixture-not-a-real-secret')
    (directory / 'daemon.pid').write_text('12345')
    (directory / 'classification.log').write_text('runtime log excluded')
    return db


def archive_of(directory):
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in directory.iterdir():
            archive.write(path, path.name)
    return memory.getvalue()


class FakeClient:
    repository = REPOSITORY
    def __init__(self, payload, runs=None, artifacts=None, writers=()):
        self.payload = payload
        self.run_list = runs or []
        self.artifact_list = artifacts or {}
        self.writers = set(writers)
        self.bootstraps = 0
        self.deleted = []
        self.repository_artifacts = []
        self.run_metadata = {}
    def runs(self, workflow, branch):
        return iter(self.run_list)
    def artifacts(self, run_id):
        return self.artifact_list.get(run_id, [])
    def collection_started(self, run_id):
        return run_id in self.writers
    def download(self, artifact_id):
        return self.payload
    def workflow_id(self, workflow):
        return 101
    def all_artifacts(self):
        return iter(self.repository_artifacts)
    def run(self, run_id):
        return self.run_metadata[run_id]
    def delete_artifact(self, artifact_id):
        self.deleted.append(artifact_id)
    def bootstrap(self, tag):
        self.bootstraps += 1
        return self.payload


def run(run_id=42, run_number=1, event='schedule'):
    return {'id': run_id, 'run_number': run_number, 'head_branch': BRANCH, 'event': event}


def artifact(run_id=42, expired=False):
    return {'id': 90, 'name': ARTIFACT_PREFIX + str(run_id), 'expired': expired}


class ActionsStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.connection = fixture(self.source)
        self.snapshot = self.root / 'snapshot'
        save_state(self.source, self.snapshot, repository=REPOSITORY, branch=BRANCH, run_id=42)
        self.payload = archive_of(self.snapshot)
    def tearDown(self):
        self.connection.close()
        self.temporary.cleanup()
    def restore(self, **kwargs):
        return restore_archive(self.payload, self.root / 'restored', repository=REPOSITORY,
                               branch=BRANCH, run_id=42, **kwargs)
    def test_wal_database_preserves_first_seen_cursors_baselines_http_and_classifications(self):
        self.restore()
        with sqlite3.connect(self.root / 'restored/intelligence.db') as db:
            self.assertEqual(db.execute('SELECT first_seen_at FROM source_items').fetchone()[0], FIRST_SEEN)
            self.assertEqual(db.execute('SELECT first_seen_at FROM unified_vulnerabilities').fetchone()[0], FIRST_SEEN)
            self.assertEqual(db.execute('SELECT started_at FROM source_observation_baselines').fetchone()[0], BASELINE)
            self.assertEqual(db.execute('SELECT cursor FROM incremental_cursors').fetchone()[0], FIRST_SEEN)
            self.assertEqual(db.execute('SELECT etag FROM document_http_state').fetchone()[0], 'etag-original')
            self.assertEqual(db.execute('SELECT state FROM ai_classifications').fetchone()[0], 'classified')
        restored_baseline = json.loads((self.root / 'restored/monitoring_baseline.json').read_text())
        self.assertEqual(restored_baseline['started_at'], BASELINE)
    def test_snapshot_excludes_credentials_locks_pid_and_logs(self):
        with zipfile.ZipFile(io.BytesIO(self.payload)) as archive:
            self.assertEqual(set(archive.namelist()), {'intelligence.db', 'monitoring_baseline.json',
                             'monitoring_status.json', 'classification_status.json', 'manifest.json'})
            self.assertNotIn(b'fixture-not-a-real-secret', b''.join(archive.read(n) for n in archive.namelist()))
    def test_checksum_failure_does_not_modify_destination(self):
        (self.snapshot / 'monitoring_baseline.json').write_text(json.dumps({'started_at': FIRST_SEEN}))
        with self.assertRaisesRegex(StateError, 'checksum'):
            restore_archive(archive_of(self.snapshot), self.root / 'restored', repository=REPOSITORY,
                            branch=BRANCH, run_id=42)
        self.assertEqual(list((self.root / 'restored').iterdir()), [])
    def test_wrong_branch_or_run_cannot_supply_state(self):
        with self.assertRaisesRegex(StateError, 'provenance'):
            restore_archive(self.payload, self.root / 'restored', repository=REPOSITORY,
                            branch='untrusted-branch', run_id=42)
        with self.assertRaisesRegex(StateError, 'provenance'):
            restore_archive(self.payload, self.root / 'restored', repository=REPOSITORY,
                            branch=BRANCH, run_id=99)
    def test_path_traversal_is_rejected_before_extracting(self):
        memory = io.BytesIO()
        with zipfile.ZipFile(memory, 'w') as archive:
            archive.writestr('../.env', 'fixture')
        with self.assertRaisesRegex(StateError, 'Unexpected'):
            restore_archive(memory.getvalue(), self.root / 'restored', repository=REPOSITORY,
                            branch=BRANCH, run_id=42)
        self.assertFalse((self.root / '.env').exists())
    def test_existing_destination_is_never_overwritten(self):
        destination = self.root / 'restored'
        destination.mkdir()
        (destination / 'marker').write_text('original')
        with self.assertRaisesRegex(StateError, 'never overwritten'):
            self.restore()
        self.assertEqual((destination / 'marker').read_text(), 'original')
    def test_latest_snapshot_is_restored_even_if_collector_run_failed(self):
        client = FakeClient(self.payload, [run()], {42: [artifact()]}, writers={42})
        with patch('sys.stdout', io.StringIO()):
            manifest = restore_latest(client, self.root / 'restored', workflow='fixture.yml',
                                      branch=BRANCH, run_id=43, run_number=2, bootstrap_release_tag='seed')
        self.assertEqual(manifest['run_id'], 42)
        self.assertEqual(client.bootstraps, 0)
    def test_missing_latest_writer_snapshot_cannot_fall_back_to_older_state_or_seed(self):
        client = FakeClient(self.payload, [run(43, 2), run()], {42: [artifact()]}, writers={42, 43})
        with self.assertRaisesRegex(StateError, 'previous collection started'):
            restore_latest(client, self.root / 'restored', workflow='fixture.yml', branch=BRANCH,
                           run_id=44, run_number=3, bootstrap_release_tag='seed')
        self.assertEqual(client.bootstraps, 0)
    def test_expired_snapshot_is_not_replaced_by_empty_database(self):
        client = FakeClient(self.payload, [run()], {42: [artifact(expired=True)]}, writers={42})
        with self.assertRaisesRegex(StateError, 'expired'):
            restore_latest(client, self.root / 'restored', workflow='fixture.yml', branch=BRANCH,
                           run_id=43, run_number=2)
    def test_only_first_run_can_start_without_seed_or_prior_snapshot(self):
        client = FakeClient(self.payload)
        with patch('sys.stdout', io.StringIO()):
            self.assertIsNone(restore_latest(client, self.root / 'restored', workflow='fixture.yml',
                                            branch=BRANCH, run_id=42, run_number=1))
        with self.assertRaisesRegex(StateError, 'refusing to reset'):
            restore_latest(client, self.root / 'restored-2', workflow='fixture.yml',
                           branch=BRANCH, run_id=43, run_number=2, bootstrap_release_tag='seed')
    def test_seed_migrates_existing_baselines_only_before_any_collection(self):
        seed_dir = self.root / 'seed'
        save_state(self.source, seed_dir, repository=REPOSITORY, branch=BRANCH, run_id=0)
        client = FakeClient(archive_of(seed_dir))
        with patch('sys.stdout', io.StringIO()):
            manifest = restore_latest(client, self.root / 'restored', workflow='fixture.yml', branch=BRANCH,
                                      run_id=42, run_number=1, bootstrap_release_tag='initial-public-state')
        self.assertEqual(manifest['run_id'], 0)
        self.assertEqual(client.bootstraps, 1)
        self.assertEqual(json.loads((self.root / 'restored/monitoring_baseline.json').read_text())['started_at'], BASELINE)
    def test_seed_can_retry_if_first_run_failed_before_collection(self):
        seed_dir = self.root / 'seed'
        save_state(self.source, seed_dir, repository=REPOSITORY, branch=BRANCH, run_id=0)
        client = FakeClient(archive_of(seed_dir), [run()])
        with patch('sys.stdout', io.StringIO()):
            manifest = restore_latest(client, self.root / 'restored', workflow='fixture.yml', branch=BRANCH,
                                      run_id=43, run_number=2, bootstrap_release_tag='initial-public-state')
        self.assertEqual(manifest['run_id'], 0)
    def test_delayed_older_run_is_blocked_after_newer_completed_writer(self):
        client = FakeClient(self.payload, [run(43, 2), run(41, 0)], {43: [artifact(43)]}, writers={43})
        with self.assertRaisesRegex(StateError, 'newer run already collected'):
            restore_latest(client, self.root / 'restored', workflow='fixture.yml', branch=BRANCH,
                           run_id=42, run_number=1, bootstrap_release_tag='seed')
        self.assertEqual(client.bootstraps, 0)
    def test_delayed_older_run_is_blocked_when_newer_writer_lost_snapshot(self):
        client = FakeClient(self.payload, [run(43, 2)], writers={43})
        with self.assertRaisesRegex(StateError, 'newer run already collected'):
            restore_latest(client, self.root / 'restored', workflow='fixture.yml', branch=BRANCH,
                           run_id=42, run_number=1, bootstrap_release_tag='seed')
        self.assertEqual(client.bootstraps, 0)
    def test_rerunning_any_historical_run_is_blocked_even_if_it_never_collected(self):
        client = FakeClient(self.payload, [run(43, 2)], {43: [artifact(43)]})
        with self.assertRaisesRegex(StateError, 'Reruns cannot write'):
            restore_latest(client, self.root / 'restored', workflow='fixture.yml', branch=BRANCH,
                           run_id=42, run_number=1, run_attempt=2, bootstrap_release_tag='seed')
        self.assertEqual(client.bootstraps, 0)
    def test_draft_bootstrap_uses_release_listing_and_fixed_same_repo_asset(self):
        client = GitHubClient('fixture-token', REPOSITORY)
        release = {'tag_name': 'initial-state', 'draft': True,
                   'assets': [{'name': BOOTSTRAP_ASSET, 'id': 17, 'size': 12}]}
        with patch.object(client, 'request', side_effect=[[release], b'fixture-archive']) as request:
            self.assertEqual(client.bootstrap('initial-state'), b'fixture-archive')
        self.assertEqual(request.call_args_list[0].args[0], 'releases?per_page=100&page=1')
        self.assertEqual(request.call_args_list[1].args[0], 'releases/assets/17')
        self.assertEqual(request.call_args_list[1].kwargs['accept'], 'application/octet-stream')
    def test_invisible_draft_seed_fails_without_creating_a_new_baseline(self):
        client = GitHubClient('fixture-token', REPOSITORY)
        with patch.object(client, 'request', return_value=[]):
            with self.assertRaisesRegex(StateError, 'draft read permission'):
                client.bootstrap('initial-state')
    def prune_client(self):
        client = FakeClient(self.payload, artifacts={10: [{'id': 110, 'name': ARTIFACT_PREFIX + '10', 'expired': False}]})
        for number in range(1, 11):
            client.repository_artifacts.append({'id': 100 + number, 'name': ARTIFACT_PREFIX + str(number),
                                                'workflow_run': {'id': number}})
            client.run_metadata[number] = {'id': number, 'run_number': number, 'workflow_id': 101,
                                           'head_branch': BRANCH, 'event': 'schedule'}
        return client
    def test_cleanup_retains_eight_latest_states_and_ignores_other_artifacts(self):
        client = self.prune_client()
        client.repository_artifacts.extend([
            {'id': 500, 'name': 'team-test-results', 'workflow_run': {'id': 11}},
            {'id': 501, 'name': ARTIFACT_PREFIX + '11', 'workflow_run': {'id': 11}},
            {'id': 502, 'name': ARTIFACT_PREFIX + '12', 'workflow_run': {'id': 12}},
            {'id': 503, 'name': ARTIFACT_PREFIX + '13', 'workflow_run': {'id': 13}},
            {'id': 504, 'name': ARTIFACT_PREFIX + '14', 'workflow_run': {'id': 999}},
        ])
        client.run_metadata.update({
            11: {'workflow_id': 999, 'head_branch': BRANCH, 'event': 'schedule', 'run_number': 11},
            12: {'workflow_id': 101, 'head_branch': 'feature', 'event': 'schedule', 'run_number': 12},
            13: {'workflow_id': 101, 'head_branch': BRANCH, 'event': 'pull_request', 'run_number': 13},
        })
        with patch('sys.stdout', io.StringIO()):
            deleted = prune_states(client, workflow='fixture.yml', branch=BRANCH, run_id=10, uploaded_artifact_id=110)
        self.assertEqual(set(deleted), {101, 102})
        self.assertEqual(set(client.deleted), {101, 102})
    def test_failed_or_unconfirmed_upload_never_deletes_old_snapshots(self):
        client = self.prune_client()
        with self.assertRaisesRegex(StateError, 'not confirmed'):
            prune_states(client, workflow='fixture.yml', branch=BRANCH, run_id=10, uploaded_artifact_id=999)
        self.assertEqual(client.deleted, [])
    def test_cleanup_metadata_failure_happens_before_any_delete(self):
        client = self.prune_client()
        with patch.object(client, 'run', side_effect=StateError('API unavailable')):
            with self.assertRaisesRegex(StateError, 'API unavailable'):
                prune_states(client, workflow='fixture.yml', branch=BRANCH, run_id=10, uploaded_artifact_id=110)
        self.assertEqual(client.deleted, [])
    def test_cross_host_archive_redirect_drops_github_token(self):
        req = urllib.request.Request('https://api.github.com/repos/team/repo/actions/artifacts/1/zip',
                                     headers={'Authorization': 'Bearer fixture-token'})
        redirect = SafeRedirect().redirect_request(req, None, 302, 'found', {}, 'https://storage.example/archive')
        self.assertIsNone(redirect.get_header('Authorization'))


if __name__ == '__main__':
    unittest.main()
