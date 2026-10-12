"""Exercise actual code collection, detail and QA using our own inert text fixture."""
import copy
from contextlib import closing
import hashlib
import importlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from enrichment import poc_sources as sources
from enrichment.sample import load_sample


class PoCSourceApiTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.db = self.root/'sources.sqlite3'
        self.catalog = self.root/'catalog.json'
        self.bodies = {'README.md': b'Synthetic fixture version 0.1.33\n',
                       'main.py': b"raise RuntimeError('must never execute fixture')\n",
                       'requirements.txt': b'fixture-library==1.0\n'}
        files = []
        for path, body in self.bodies.items():
            files.append({'path':path, 'size':len(body), 'sha256':hashlib.sha256(body).hexdigest(),
                          'git_blob_sha':hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()})
        self.candidate = {'cve_id':'CVE-2024-37032','candidate_id':'api-fixture',
            'repository':'fixture/own-api-fixture','commit_sha':'a'*40,'files':files,
            'review':{'reviewed_by':'development_agent','review_method':'manual_source_read_and_ast',
                'summary':'这是归档测试的合成来源，不是真实利用代码。','runtime_validation':'not_run',
                'dependencies_file':'requirements.txt','capability':'fixture_only',
                'target_version_claim':{'version':'0.1.33','file':'README.md','lines':[1,1]},
                'findings':[{'text':'测试源码不会被执行。','file':'main.py','lines':[1,1]}]}}
        self.catalog.write_text(json.dumps({'candidates':[self.candidate]},ensure_ascii=False),encoding='utf-8')
        self.calls = []
        def fetch(url, deadline):
            self.calls.append(url)
            return self.bodies[url.rsplit('/',1)[-1]]
        for manager in (patch.object(sources,'DEFAULT_DB',self.db), patch.object(sources,'CATALOG_PATH',self.catalog),
                        patch.object(sources,'_fetch',side_effect=fetch),
                        patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('network forbidden'))):
            manager.start()
            self.addCleanup(manager.stop)
        self.app_module = importlib.import_module('api.app')
        self.client = TestClient(self.app_module.app)
        self.record, _ = load_sample()
        manager = patch('api.app.get_record',return_value=self.record)
        manager.start()
        self.addCleanup(manager.stop)

    def collect(self):
        response = self.client.post('/api/poc-code/CVE-2024-37032/collect',json={})
        self.assertEqual(response.status_code,200,response.text)
        return response.json()

    def test_get_before_collection_never_fetches_or_creates_database(self):
        response = self.client.get('/api/poc-code/CVE-2024-37032')
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['status'],'not_collected')
        self.assertEqual(self.calls,[])
        self.assertFalse(self.db.exists())

    def test_collect_publishes_fixed_files_and_get_is_read_only(self):
        report = self.collect()
        self.assertEqual(report['status'],'static_reviewed')
        self.assertEqual(len(self.calls),3)
        self.assertEqual(report['validation'],'not_run')
        self.assertEqual(report['items'][0]['availability'],'pending')
        self.calls.clear()
        before = self.db.read_bytes()
        response = self.client.get('/api/poc-code/CVE-2024-37032')
        self.assertEqual(response.status_code,200)
        self.assertEqual(self.calls,[])
        self.assertEqual(self.db.read_bytes(),before)
        self.assertTrue(all(row['citation_id'].startswith('CVE-2024-37032/') for row in response.json()['evidence']))

    def test_client_cannot_supply_download_url_command_or_verification_status(self):
        for body in ({'url':'http://127.0.0.1/secret'}, {'command':'anything'}, {'validation':'runtime_verified'}):
            with self.subTest(body=body):
                self.assertEqual(self.client.post('/api/poc-code/CVE-2024-37032/collect',json=body).status_code,422)
        self.assertEqual(self.calls,[])
        self.assertFalse(self.db.exists())

    def test_invalid_missing_and_unconfigured_cves_have_distinct_results(self):
        self.assertEqual(self.client.get('/api/poc-code/invalid').status_code,422)
        with patch('api.app.get_record',return_value=None):
            self.assertEqual(self.client.post('/api/poc-code/CVE-2099-99999/collect').status_code,404)
        response = self.client.get('/api/poc-code/CVE-2025-0312')
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['status'],'unconfigured')
        self.assertEqual(self.calls,[])
        self.assertFalse(self.db.exists())

    def test_failed_refresh_retains_source_and_marks_current_failure(self):
        self.collect()
        with patch.object(sources,'_fetch',side_effect=TimeoutError('fixture timeout')):
            result = self.collect()
        self.assertEqual(result['status'],'static_reviewed')
        self.assertEqual(result['latest_attempt']['status'],'error')
        self.assertTrue(result['items'][0]['retained_previous'])
        self.assertEqual(len(result['items'][0]['files']),3)

    def test_storage_failure_is_503_without_success_acknowledgement(self):
        for error in (sqlite3.OperationalError('fixture database locked'), OSError('fixture disk failure')):
            with self.subTest(error=type(error).__name__), patch.object(sources,'collect',side_effect=error):
                response = self.client.post('/api/poc-code/CVE-2024-37032/collect')
                self.assertEqual(response.status_code,503,response.text)

    def test_tampered_source_is_removed_from_report(self):
        self.collect()
        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute('DELETE FROM poc_files WHERE path=?',('main.py',))
        response = self.client.get('/api/poc-code/CVE-2024-37032')
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['status'],'error')
        self.assertEqual(response.json()['facts'],[])
        self.assertEqual(response.json()['evidence'],[])

    def test_item_detail_exposes_view_without_collecting(self):
        report = self.collect()
        self.record['item'].setdefault('raw_data',{})['poc_code']=report
        self.calls.clear()
        with patch('rag.ingest.document_status',return_value={'status':'empty'}):
            response = self.client.get('/api/items/CVE-2024-37032')
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['poc_code']['status'],'static_reviewed')
        self.assertEqual(self.calls,[])

    def test_qa_excerpts_current_provenance_even_when_model_configured(self):
        from agents.qa_agent import run
        from agents.verifier_agent import run as verify
        report = self.collect()
        self.record['item'].setdefault('raw_data',{})['poc_code']=report
        self.calls.clear()
        with patch('agents.qa_agent.search',return_value=[self.record]), patch('agents.qa_agent.configured',return_value=True), patch('agents.qa_agent.chat') as chat:
            answer = run('CVE-2024-37032 的 PoC 来源、代码摘要和依赖是什么？')
        self.assertFalse(answer['used_model'])
        chat.assert_not_called()
        self.assertEqual(self.calls,[])
        self.assertIn('fixture/own-api-fixture',answer['answer'])
        self.assertIn('fixture-library==1.0',answer['answer'])
        self.assertIn('本项目未运行该代码',answer['answer'])
        self.assertTrue(verify(answer['answer'],answer['evidence'])['passed'])

    def test_project_poc_status_question_is_not_routed_to_assets(self):
        from agents.qa_agent import run
        report = self.collect()
        self.record['item'].setdefault('raw_data',{})['poc_code']=report
        with patch('agents.qa_agent.search',return_value=[self.record]), patch('enrichment.assets.answer_assets') as assets:
            answer = run('我们的 CVE-2024-37032 PoC 已经复现了吗？')
        assets.assert_not_called()
        self.assertIn('未运行',answer['answer'])

    def test_runtime_verified_field_does_not_authorize_positive_reproduction_claim(self):
        from agents.verifier_agent import run as verify
        report = self.collect()
        record = copy.deepcopy(self.record)
        record['evidence_chunks']=report['evidence']
        record['poc']=[{'url':'https://github.com/fixture/own-api-fixture','validation':'runtime_verified'}]
        citation=report['evidence'][0]['citation_id']
        result = verify('本项目已成功复现 CVE-2024-37032 PoC。 ['+citation+']',[record])
        self.assertFalse(result['passed'])
        self.assertTrue(any('实验台账' in message for message in result['notes']))

    def test_current_code_view_is_attached_to_retrieval_without_network(self):
        from rag.retrieve import _attach_guidance
        self.collect()
        self.calls.clear()
        with patch('rag.retrieve.library_for',return_value=None):
            record = _attach_guidance(copy.deepcopy(self.record),self.db,poc_db=self.db)
        self.assertEqual(record['item']['raw_data']['poc_code']['status'],'static_reviewed')
        self.assertEqual(self.calls,[])

    def test_temporary_evidence_database_does_not_borrow_production_poc(self):
        from rag.retrieve import _attach_guidance
        self.collect()
        self.calls.clear()
        with patch('rag.retrieve.library_for',return_value=None), patch.object(sources,'report',wraps=sources.report) as read:
            record = _attach_guidance(copy.deepcopy(self.record),self.root/'frozen-evidence.sqlite3')
        read.assert_not_called()
        self.assertEqual(record['item']['raw_data']['poc_code']['status'],'unconfigured')
        self.assertEqual(record['item']['raw_data']['poc_code']['facts'],[])
        self.assertEqual(self.calls,[])


if __name__ == '__main__':
    unittest.main()
