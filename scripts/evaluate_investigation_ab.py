"""Real-model / rules paired evaluation against frozen real provider responses.

Production SQLite is opened read-only. Only selected evidence is copied; all
provider writes, query cursors and runs stay under --output. Provider handlers
and the production planner are unchanged. The model is live; provider HTTP is
captured once then replayed byte-for-byte. This measures bounded tool routing,
not semantic accuracy or live network latency. No reviews are auto-created.
"""
import argparse
import copy
import csv
from contextlib import ExitStack, closing
from datetime import datetime, timedelta, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import statistics
import subprocess
import sys
import time
from unittest.mock import patch
import urllib.request
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TZ = timezone(timedelta(hours=8))
CVES = ("CVE-2024-37032", "CVE-2024-45436", "CVE-2025-0312")
TABLES = ("records", "evidence", "documents", "document_attempts", "source_snapshots")


def stamp():
    return datetime.now(TZ).isoformat()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha(value):
    return hashlib.sha256(value).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def db_hash(path):
    """Logical content hash, independent of WAL checkpoints and SQLite pages."""
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        return sha("\n".join(conn.iterdump()).encode())


def sqlite_file_path(database):
    text = os.fspath(database)
    if text.startswith('file:'):
        parsed = urlsplit(text)
        if parsed.netloc not in ('', 'localhost'):
            raise RuntimeError('Nonlocal SQLite URI blocked')
        return Path(urllib.request.url2pathname(parsed.path)).resolve()
    return Path(text).resolve()


def quality_hash(path):
    """Only immutable quality tables; ongoing observation snapshots may change."""
    digest = hashlib.sha256()
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as conn:
        for table in ('quality_runs', 'quality_cases', 'quality_reviews', 'quality_datasets'):
            digest.update(table.encode())
            rows = conn.execute('SELECT * FROM "' + table + '" ORDER BY 1,2').fetchall()
            for row in rows:
                digest.update(canonical(row).encode())
    return digest.hexdigest()


def copy_evidence(source, target, cve_id):
    target.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)) as src, closing(sqlite3.connect(target)) as dst:
        for table in TABLES:
            schema = src.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            dst.execute(schema[0])
            rows = src.execute('SELECT * FROM "' + table + '" WHERE cve_id=?', (cve_id,)).fetchall()
            if rows:
                dst.executemany('INSERT INTO "' + table + '" VALUES (' + ','.join('?' for _ in rows[0]) + ')', rows)
        dst.commit()


class FrozenHTTP:
    def __init__(self, directory):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self.recording = True
        self.used = []
        self.misses = []

    def response(self, kind, url, loader):
        key = sha((kind + ':' + url).encode())
        meta_path, body_path = self.directory / (key + '.json'), self.directory / (key + '.body')
        if not meta_path.exists():
            if not self.recording:
                self.misses.append({'kind': kind, 'url': url})
                raise RuntimeError('Unrecorded provider request blocked')
            started = time.perf_counter()
            metadata = {'kind': kind, 'url': url, 'captured_at': stamp()}
            try:
                value = loader()
                body = value.pop('body')
                metadata.update(value, status='ok', response_sha256=sha(body), bytes=len(body))
                body_path.write_bytes(body)
            except Exception as exc:
                metadata.update(status='error', error_type=type(exc).__name__, error=str(exc)[:300])
            metadata['capture_elapsed_ms'] = round((time.perf_counter() - started) * 1000, 3)
            save(meta_path, metadata)
        metadata = json.loads(meta_path.read_text(encoding='utf-8'))
        self.used.append(key)
        if metadata['status'] != 'ok':
            raise RuntimeError('Frozen provider error: ' + metadata['error_type'] + ': ' + metadata['error'])
        body = body_path.read_bytes()
        if sha(body) != metadata['response_sha256']:
            raise RuntimeError('Frozen response hash mismatch')
        return {**metadata, 'body': body}

    def document(self, url):
        from enrichment.documents import fetch
        result = self.response('document', url, lambda: fetch(url))
        return {key: result[key] for key in ('body', 'content_type', 'url', 'encoding')}

    def feed(self, url, timeout):
        def load():
            request = urllib.request.Request(url, headers={'User-Agent': 'ai-sec-intel-student'})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(8 * 1024 * 1024 + 1)
                if len(body) > 8 * 1024 * 1024:
                    raise ValueError('Provider response exceeds 8 MiB')
                json.loads(body)
                return {'body': body, 'url': response.geturl()}
        return json.loads(self.response('feed', url, load)['body'])

    def paper(self, url):
        from enrichment.papers import _fetch
        return self.response('paper', url, lambda: {'body': self.real_paper_fetch(url)})['body']

    def manifest(self):
        return [json.loads(p.read_text(encoding='utf-8')) for p in sorted(self.directory.glob('*.json'))]


def scenarios():
    # Predeclared before any model request; one-call pairs reveal routing impact.
    specs = [('feeds', CVES[0], True, False), ('archive_feeds', CVES[1], True, True),
             ('archive', CVES[2], False, True)]
    result = []
    for name, cve, hide_feeds, hide_archive in specs:
        for budget in (1, 4):
            result.append({'id': name + '-' + str(budget), 'cve_id': cve,
                           'hide_feeds': hide_feeds, 'hide_archive': hide_archive,
                           'tool_budget': budget, 'model_budget': 2, 'seconds': 90})
    result.append({'id': 'single-tool-control', 'cve_id': CVES[0], 'hide_feeds': False,
                   'hide_archive': False, 'tool_budget': 4, 'model_budget': 2, 'seconds': 90})
    return result


def validate_resolved(result, initial, cache):
    """Source/status checks; not a human semantic correctness judgement."""
    assessment, record = result['assessment'], result['record']
    cid = record['item']['cve_id']
    resolved = set(initial) - set(result['remaining_gaps'])
    good, rejected = [], []
    from enrichment.service import EPSS_URL, KEV_URL
    for gap in sorted(resolved):
        valid = False
        if gap in {'evidence_archive', 'cvss', 'affected_versions', 'source_conflict'}:
            bound = bool(assessment.get('source', {}).get('sha256') and assessment.get('evidence'))
            if gap == 'evidence_archive':
                valid = bound and assessment.get('status') in {'ok', 'partial'}
            elif gap == 'cvss':
                valid = bound and bool((assessment.get('cvss') or {}).get('evidence_ids'))
            elif gap == 'affected_versions':
                valid = bound and bool(assessment.get('affected_ranges')) and all(r.get('evidence_ids') for r in assessment['affected_ranges'])
            else:
                from agents.investigation import _source_conflicts
                valid = bound and not _source_conflicts(assessment)
        elif gap == 'exploit_probability':
            payload = cache.feed(EPSS_URL % cid, 20)
            rows = [r for r in payload.get('data', []) if r.get('cve') == cid]
            value = record.get('epss') or {}
            valid = len(rows) == 1 and value.get('status') == 'ok' and all(str(value.get(k)) == str(rows[0].get(v)) for k, v in [('score', 'epss'), ('percentile', 'percentile'), ('source_date', 'date')])
        elif gap == 'known_exploitation':
            payload = cache.feed(KEV_URL, 25)
            entries = payload.get('vulnerabilities', [])
            listed = any(x.get('cveID') == cid for x in entries)
            valid = payload.get('count') == len(entries) and (record.get('kev') or {}).get('status') == ('listed' if listed else 'not_listed')
        elif gap == 'research_evidence':
            # Independent byte provenance check against captured arXiv feed.
            snapshots = {m.get('response_sha256') for m in cache.manifest() if m['kind'] == 'paper' and m['status'] == 'ok'}
            papers = record.get('papers') or []
            valid = bool(papers) and all(p.get('feed_response_sha256') in snapshots and cid.lower() in (p.get('title', '') + ' ' + p.get('summary', '')).lower() for p in papers)
        (good if valid else rejected).append(gap)
    return {'source_checked_resolved_gaps': good, 'unverified_resolved_gaps': rejected}


def run_arm(spec, repetition, arm, directory, seed, record, cache, library, settings):
    from agents import investigation as agent
    from config.llm import chat as real_chat
    from enrichment import service, papers, research_associations
    from rag.ingest import ingest
    directory.mkdir(parents=True, exist_ok=True)
    db = directory / 'task_c.sqlite3'
    shutil.copy2(seed, db)
    working = copy.deepcopy(record)
    if spec['hide_feeds']:
        working['epss'] = None
        working['kev'] = None
    if spec['hide_archive']:
        with closing(sqlite3.connect(db)) as conn:
            for table in TABLES[1:]:
                conn.execute('DELETE FROM "' + table + '"')
            conn.commit()
    before_hash = db_hash(db)
    save(directory / 'initial-record.json', working)
    model_records, sqlite_attempts, blocked = [], [], []
    real_connect, real_socket_connect = sqlite3.connect, socket.socket.connect

    def guarded_sqlite(database, *args, **kwargs):
        candidate = sqlite_file_path(database)
        if not candidate.is_relative_to(directory.parents[3].resolve()):
            raise RuntimeError('SQLite outside isolation root blocked: ' + str(candidate))
        sqlite_attempts.append(str(candidate))
        return real_connect(database, *args, **kwargs)

    def guarded_socket(sock, address):
        if isinstance(address, tuple) and address[0] in ('127.0.0.1', '::1') and address[1] == 11434:
            return real_socket_connect(sock, address)
        blocked.append(str(address))
        raise RuntimeError('Only the local model network endpoint is allowed during replay')

    def tracked_chat(messages, **kwargs):
        request = {'messages': copy.deepcopy(messages), 'options': kwargs, 'started_at': stamp()}
        started = time.perf_counter()
        model_records.append(request)
        try:
            request['response'] = real_chat(messages, **kwargs)
            request['status'] = 'ok'
            return request['response']
        except Exception as exc:
            request.update(status='error', error_type=type(exc).__name__)
            raise
        finally:
            request['elapsed_ms'] = round((time.perf_counter() - started) * 1000, 3)

    original_refresh = research_associations.refresh
    def local_refresh(value, **kwargs):
        kwargs['library_db'] = library
        return original_refresh(value, **kwargs)

    start_used = len(cache.used)
    with ExitStack() as stack:
        stack.enter_context(patch.object(agent, 'chat', tracked_chat))
        stack.enter_context(patch.object(agent, 'ingest', lambda r, **kw: ingest(r, fetcher=cache.document, **kw)))
        stack.enter_context(patch.object(service, '_get_json', cache.feed))
        stack.enter_context(patch.object(papers, '_fetch', cache.paper))
        stack.enter_context(patch.object(research_associations, 'refresh', local_refresh))
        stack.enter_context(patch.object(sqlite3, 'connect', guarded_sqlite))
        stack.enter_context(patch.object(socket.socket, 'connect', guarded_socket))
        if spec.get('candidate_order') == 'reversed':
            original_available = agent._available
            stack.enter_context(patch.object(agent, '_available', lambda gaps, attempted: list(reversed(original_available(gaps, attempted)))))
        result = agent.run(working, db_path=db, use_model=arm == 'model',
                           max_tool_calls=spec['tool_budget'], max_model_calls=spec['model_budget'],
                           time_budget_seconds=spec['seconds'])
    trace = result['trace']
    if 'assessment_error' in trace.get('errors', []):
        save(directory / 'invalid-result.json', result)
        raise RuntimeError('Assessment failed; reject this experiment rather than count false gaps')
    validation = validate_resolved(result, trace['initial_gaps'], cache)
    decisions = trace['decisions']
    unsupported = [d['step'] for d in decisions if d['tool'] not in d['available_tools']]
    eligible = [d for d in decisions if len(d['available_tools']) > 1]
    model_selections = [d for d in decisions if d['selected_by'] == 'model']
    for d in decisions:
        d['rules_choice_in_same_state'] = agent._rules(d['available_tools'], working)
    models_diverging = sum(d['tool'] != d['rules_choice_in_same_state'] for d in model_selections)
    initial_hash = sha(canonical({'record': working, 'database': before_hash}).encode())
    metrics = {'scenario': spec['id'], 'cve_id': spec['cve_id'], 'repetition': repetition,
               'arm': arm, 'initial_hash': initial_hash, 'initial_gaps': trace['initial_gaps'],
               'tool_calls': len(trace['calls']), 'multiple_choice_steps': len(eligible),
               'model_attempts': trace['model_calls'], 'accepted_model_choices': len(model_selections),
               'choices_different_from_rules': models_diverging,
               'fallbacks': sum(bool(d.get('model_fallback')) for d in decisions),
               'unsupported_calls': len(unsupported),
               'no_gap_reduction_calls': sum(not c['resolved_gaps'] for c in trace['calls']),
               'failed_tool_calls': sum(c['status'] in ('error', 'partial') for c in trace['calls']),
               'resolved_gaps': sorted(set(trace['initial_gaps']) - set(trace['remaining_gaps'])),
               'remaining_gaps': trace['remaining_gaps'], **validation,
               'elapsed_ms': trace['elapsed_ms'],
               'model_elapsed_ms': round(sum(x['elapsed_ms'] for x in model_records), 3),
               'tool_elapsed_ms': sum(c['duration_ms'] for c in trace['calls']),
               'tools': [c['tool'] for c in trace['calls']], 'stop_reason': trace['stop_reason'],
               'provider_response_keys': sorted(set(cache.used[start_used:])),
               'blocked_network_attempts': blocked, 'sqlite_paths': sorted(set(sqlite_attempts))}
    save(directory / 'result.json', result)
    save(directory / 'model-io.json', model_records)
    save(directory / 'metrics.json', metrics)
    return metrics


def render_report(report, output):
    esc = lambda x: html.escape(str(x))
    rows = []
    for pair in report['pairs']:
        a, b = pair['rules'], pair['model']
        rows.append('<tr>' + ''.join('<td>' + esc(v) + '</td>' for v in [pair['scenario'], pair['repetition'],
                    ' → '.join(a['tools']), ' → '.join(b['tools']),
                    str(len(a['source_checked_resolved_gaps'])) + ' / ' + str(len(b['source_checked_resolved_gaps'])),
                    str(b['accepted_model_choices']) + ' / ' + str(b['model_attempts']),
                    str(a['no_gap_reduction_calls']) + ' / ' + str(b['no_gap_reduction_calls']),
                    str(b['fallbacks']), f"{a['elapsed_ms']/1000:.2f} / {b['elapsed_ms']/1000:.2f}"]) + '</tr>')
    summary_rows = ''.join('<tr><td>' + esc(k) + '</td><td>' + esc(v) + '</td></tr>' for k, v in report['summary'].items())
    content = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Agent 自主工具调用对照验证</title>
<style>body{font:14px/1.65 "Segoe UI","Microsoft YaHei",sans-serif;color:#17212f;background:#f4f6f8;margin:0}main{max-width:1500px;margin:32px auto;padding:0 24px}h1{font-size:26px}h2{font-size:18px}section{background:white;border:1px solid #e0e5ec;border-radius:8px;padding:24px;margin:20px 0}table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #e0e5ec;padding:10px;overflow-wrap:anywhere}th{background:#f4f6f8}small{color:#556273}.scroll{overflow:auto}a{color:#2563eb}code{font-family:Consolas,monospace}details{margin:16px 0}pre{white-space:pre-wrap;word-break:break-word}.notice{border-left:4px solid #2563eb;padding:8px 16px;background:#eff4ff}@media(max-width:700px){main{padding:0 12px}section{padding:16px}}</style><main><h1>Agent 自主工具调用对照验证</h1>'''
    content += '<p>生成时间：' + esc(report['generated_at']) + ' · 代码：<code>' + esc(report['source_commit']) + '</code></p>'
    content += '<section><h2>验证范围与结论</h2><p class="notice">' + esc(report['conclusion']) + '</p>'
    content += '<p>模型实际调用本机 ' + esc(report['model']['model']) + '；工具使用真实 HTTP 响应的冻结回放，原采集及解析处理函数保持不变。正式数据库只读，未修改网页配置或人工复核。</p><table>' + summary_rows + '</table></section>'
    content += '<section><h2>逐组对照</h2><p>补齐数、无缺口减少次数与耗时均按“规则 / 模型”排列；模型选择按“已采纳 / 尝试”排列。无缺口减少不自动等于无价值；未找到论文也是如实返回的检索结果。</p><div class="scroll"><table><thead><tr><th>场景</th><th>轮次</th><th>规则工具顺序</th><th>模型工具顺序</th><th>补齐检查项</th><th>模型选择</th><th>无缺口减少</th><th>模型回退</th><th>回放耗时 秒</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div></section>'
    content += '<section><h2>每次决策的原始证据</h2><p>点击场景展开，检查缺口、候选工具、模型原始返回、实际执行与结果。保存的是工具选择输出，不是模型内部思维链。</p>'
    for pair in report['pairs']:
        for arm in ('model', 'rules'):
            rel = f"runs/{pair['scenario']}/r{pair['repetition']}/{arm}"
            content += '<details><summary>' + esc(pair['scenario'] + ' · 第' + str(pair['repetition']) + '轮 · ' + arm) + '</summary>'
            content += '<p><a href="' + rel + '/result.json">完整执行轨迹</a> · <a href="' + rel + '/model-io.json">模型输入与原始输出</a> · <a href="' + rel + '/metrics.json">指标</a></p>'
            for name in ('model-io.json', 'result.json'):
                obj = json.loads((output / rel / name).read_text(encoding='utf-8'))
                display = obj.get('trace', obj) if isinstance(obj, dict) else obj
                content += '<pre>' + esc(json.dumps(display, ensure_ascii=False, indent=2)) + '</pre>'
            content += '</details>'
    content += '</section><section><h2>口径和限制</h2><ul>' + ''.join('<li>' + esc(x) + '</li>' for x in report['limitations']) + '</ul></section></main></html>'
    (output / 'report.html').write_text(content, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repetitions', type=int, default=3, choices=range(1, 6))
    parser.add_argument('--provider-snapshot', type=Path, help='Reuse a previously captured HTTP directory; never recapture to improve results')
    parser.add_argument('--catalog-order', choices=('original', 'reversed'), default='original', help='Exploratory routing robustness probe; do not mix with production-order comparison')
    parser.add_argument('--bounded-only', action='store_true', help='Only the predeclared one-tool scenarios')
    parser.add_argument('--initial-snapshot', type=Path, help='Reuse the prior snapshot/library.sqlite3 and snapshot/CVE-*/task_c.sqlite3 for identical-input replication')
    args = parser.parse_args()
    data, output = args.data.resolve(), args.output.resolve()
    if output.exists():
        parser.error('Use a new output directory; never overwrite an experiment')
    if output.is_relative_to(data) or data.is_relative_to(output):
        parser.error('Output must be separate from production data')
    settings = json.loads(args.settings.read_text(encoding='utf-8-sig'))
    if settings.get('base_url') != 'http://127.0.0.1:11434/v1':
        parser.error('This harness only permits the configured local Ollama endpoint')
    output.mkdir(parents=True)
    isolated_settings = {k: settings.get(k, '') for k in ('model', 'base_url', 'model_reasoning_effort')}
    save(output / 'model-settings.json', isolated_settings)
    os.environ.update(MAIN_DATA_DIR=str(output / 'runtime'), APP_SETTINGS_PATH=str(output / 'model-settings.json'),
                      MAIN_KB_DB_PATH=str(output / 'runtime' / 'knowledge.sqlite3'), OFFLINE_DEMO='0',
                      PYTHONUTF8='1', HF_HUB_OFFLINE='1')
    from agents import investigation as agent
    from enrichment import service, papers
    from rag.ingest import ingest
    from rag.evidence import load_record
    from enrichment.documents import fetch
    from enrichment.assessment import assess
    if not agent.configured():
        parser.error('Local model is not configured')
    source_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    specs = scenarios()
    if args.bounded_only:
        specs = [s for s in specs if s['tool_budget'] == 1]
    if args.catalog_order == 'reversed':
        for spec in specs:
            spec['candidate_order'] = 'reversed'
            spec['id'] += '-reversed'
    manifest = {'started_at': stamp(), 'source_commit': source_commit, 'model': isolated_settings,
                'repetitions': args.repetitions, 'scenarios': specs, 'candidate_order': args.catalog_order,
                'design': 'real live planner, original handlers, frozen provider HTTP; explicit missing-evidence perturbations only',
                'production_read_only': True}
    save(output / 'design.json', manifest)
    shutil.copy2(Path(__file__), output / 'runner-used.py')
    save(output / 'runner-provenance.json', {'script_sha256': sha(Path(__file__).read_bytes()),
         'agent_sha256': sha((ROOT / 'agents' / 'investigation.py').read_bytes()), 'source_commit': source_commit})
    library = output / 'snapshot' / 'library.sqlite3'
    library.parent.mkdir(parents=True, exist_ok=True)
    snapshot_source = args.initial_snapshot.resolve() if args.initial_snapshot else data
    with closing(sqlite3.connect((snapshot_source / 'library.sqlite3').as_uri() + '?mode=ro', uri=True)) as src, closing(sqlite3.connect(library)) as dst:
        src.backup(dst)
    retrieval = snapshot_source / 'library.retrieval.json'
    if retrieval.exists():
        shutil.copy2(retrieval, library.with_suffix('.retrieval.json'))
    seeds, records = {}, {}
    for cid in CVES:
        seed = output / 'snapshot' / cid / 'task_c.sqlite3'
        evidence_source = snapshot_source / cid / 'task_c.sqlite3' if args.initial_snapshot else data / 'task_c.sqlite3'
        copy_evidence(evidence_source, seed, cid)
        seeds[cid] = seed
        records[cid] = load_record(cid, seed)
        if not records[cid] or (records[cid]['item'].get('raw_data') or {}).get('sample_mode'):
            raise RuntimeError('Expected an actual stored public CVE')
        save(seed.parent / 'original-record.json', records[cid])
    before_settings = sha(args.settings.read_bytes())
    acceptance = data / 'acceptance.sqlite3'
    before_quality = quality_hash(acceptance)
    cache = FrozenHTTP(output / 'http')
    cache.real_paper_fetch = papers._fetch
    if args.provider_snapshot:
        for source in args.provider_snapshot.resolve().iterdir():
            if source.is_file() and source.suffix in ('.json', '.body'):
                shutil.copy2(source, cache.directory / source.name)
        cache.recording = False
    # Freeze all applicable providers once, before any planner decision.
    for cid in CVES:
        print('Capturing real provider evidence: ' + cid, flush=True)
        capture = output / 'capture' / cid
        capture.mkdir(parents=True)
        db = capture / 'task_c.sqlite3'
        shutil.copy2(seeds[cid], db)
        observation = {'document': ingest(copy.deepcopy(records[cid]), db_path=db, fetcher=cache.document, update_index_on_ingest=False)}
        with patch.object(service, '_get_json', cache.feed):
            value = copy.deepcopy(records[cid])
            observation['feeds'] = service.apply_public_feeds([value])
            observation['record_after_feeds'] = {'epss': value.get('epss'), 'kev': value.get('kev')}
        with patch.object(papers, '_fetch', cache.paper):
            rows, error = papers.fetch_papers([cid], max_batches=1, cursor_path=capture / 'paper_queries.sqlite3')
            observation['papers'] = {'rows': dict(rows), 'error': error}
        save(capture / 'observations.json', observation)
    cache.recording = False
    save(output / 'http-manifest.json', cache.manifest())
    if cache.misses:
        raise RuntimeError('Provider snapshot incomplete; reject this experiment')
    # Warm-up uses the real endpoint, is recorded and excluded from both arms.
    warm_start = time.perf_counter()
    try:
        warm = agent.chat([{'role': 'user', 'content': '只输出 JSON：{"ready":true}'}], timeout=60, max_tokens=32, response_format={'type': 'json_object'})
        save(output / 'warmup.json', {'status': 'ok', 'response': warm, 'elapsed_ms': (time.perf_counter()-warm_start)*1000})
    except Exception as exc:
        save(output / 'warmup.json', {'status': 'error', 'error_type': type(exc).__name__})
    pairs = []
    for index, spec in enumerate(specs):
        for repetition in range(1, args.repetitions + 1):
            arms = ('rules', 'model') if (index + repetition) % 2 else ('model', 'rules')
            pair = {'scenario': spec['id'], 'repetition': repetition, 'execution_order': arms}
            for arm in arms:
                print(f"Evaluating {spec['id']} repeat {repetition}/{args.repetitions}: {arm}", flush=True)
                directory = output / 'runs' / spec['id'] / ('r' + str(repetition)) / arm
                pair[arm] = run_arm(spec, repetition, arm, directory, seeds[spec['cve_id']], records[spec['cve_id']], cache, library, isolated_settings)
            pair['same_initial_state'] = pair['rules']['initial_hash'] == pair['model']['initial_hash']
            if not pair['same_initial_state']:
                raise RuntimeError('Paired initial state mismatch')
            pairs.append(pair)
            save(output / 'progress.json', {'pairs_completed': len(pairs), 'pairs': pairs})
    all_metrics = [pair[arm] for pair in pairs for arm in ('rules', 'model')]
    models = [p['model'] for p in pairs]
    rules = [p['rules'] for p in pairs]
    summary = {'paired_comparisons': len(pairs), 'initial_state_identical_pairs': sum(p['same_initial_state'] for p in pairs),
               'model_attempts': sum(m['model_attempts'] for m in models),
               'accepted_model_choices': sum(m['accepted_model_choices'] for m in models),
               'model_choices_different_from_rules': sum(m['choices_different_from_rules'] for m in models),
               'fallbacks': sum(m['fallbacks'] for m in models),
               'unsupported_calls': sum(m['unsupported_calls'] for m in all_metrics),
               'model_more_source_checked_gaps_pairs': sum(len(p['model']['source_checked_resolved_gaps']) > len(p['rules']['source_checked_resolved_gaps']) for p in pairs),
               'equal_source_checked_gaps_pairs': sum(len(p['model']['source_checked_resolved_gaps']) == len(p['rules']['source_checked_resolved_gaps']) for p in pairs),
               'rules_more_source_checked_gaps_pairs': sum(len(p['rules']['source_checked_resolved_gaps']) > len(p['model']['source_checked_resolved_gaps']) for p in pairs),
               'rules_total_source_checked_gaps': sum(len(m['source_checked_resolved_gaps']) for m in rules),
               'model_total_source_checked_gaps': sum(len(m['source_checked_resolved_gaps']) for m in models),
               'rules_no_gap_reduction_calls': sum(m['no_gap_reduction_calls'] for m in rules),
               'model_no_gap_reduction_calls': sum(m['no_gap_reduction_calls'] for m in models),
               'rules_median_replay_seconds': round(statistics.median(m['elapsed_ms'] for m in rules)/1000, 3),
               'model_median_replay_seconds': round(statistics.median(m['elapsed_ms'] for m in models)/1000, 3),
               'unrecorded_provider_requests': len(cache.misses),
               'blocked_network_attempts': sum(len(m['blocked_network_attempts']) for m in all_metrics),
               'production_model_settings_unchanged': before_settings == sha(args.settings.read_bytes()),
               'production_quality_records_unchanged': before_quality == quality_hash(acceptance)}
    accepted = summary['accepted_model_choices']
    diff = summary['model_choices_different_from_rules']
    conclusion = f'实际模型选择被采纳 {accepted} 次，其中 {diff} 次与同状态规则选择不同。'
    if args.catalog_order == 'reversed':
        conclusion = '候选顺序扰动探针（单独分析，不代表生产顺序下的性能优势）：' + conclusion
    if summary['model_more_source_checked_gaps_pairs']:
        conclusion += f" 模型在 {summary['model_more_source_checked_gaps_pairs']} 组补齐更多检查项；仅为本批受控样本结果。"
    else:
        conclusion += ' 本批未观察到模型补齐更多检查项，不能声称效果优于规则。'
    report = {**manifest, 'generated_at': stamp(), 'pairs': pairs, 'summary': summary, 'conclusion': conclusion,
              'limitations': ['实际模型选择在生产同款工具白名单内完成；候选集合由规则按缺口筛选，单一候选不调用模型。',
                 '初始证据缺失通过副本中显式移除字段或存档构造，属于受控消融，不是生产故障频率。',
                 '3个真实CVE的小样本开发验证；重复轮次不是独立漏洞样本，不据此计算全库准确率或显著性。',
                 '补齐数为来源和字段一致性检查通过的缺口检查项；部分检查项共享同一来源，不是独立事实条数，也不是49条人审准确率。',
                 'HTTP回放耗时排除公网延迟，包含本地解析、数据库、检索及真实模型耗时；真实采集耗时单独保存在HTTP清单中。',
                 '无缺口减少不直接等于无效：论文检索无结果、来源冲突继续存在均如实保留。',
                 '运行顺序交替、模型预热单列；生产模型可能同时处理后台请求，耗时仍可能受资源争用影响。',
                 '仅保存模型工具选择输出和可观察调用，不生成或推测模型内部推理过程。']}
    if args.catalog_order == 'reversed':
        report['limitations'].append('本组刻意颠倒候选工具顺序，两臂收到相同顺序；规则的默认顺序行为也随之改变，不能与正常顺序的规则性能混为一谈。')
    save(output / 'report.json', report)
    save(output / 'isolation-check.json', {k:v for k,v in summary.items() if 'unchanged' in k or 'blocked' in k or 'unrecorded' in k})
    fields = ['scenario','repetition','arm','tool_calls','model_attempts','accepted_model_choices','choices_different_from_rules','fallbacks','unsupported_calls','no_gap_reduction_calls','elapsed_ms','model_elapsed_ms','tool_elapsed_ms']
    with (output / 'metrics.csv').open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
        writer.writeheader(); writer.writerows(all_metrics)
    render_report(report, output)
    print(json.dumps({'output': str(output), 'summary': summary, 'conclusion': conclusion}, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
