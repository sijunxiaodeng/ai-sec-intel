"""Isolate source failures and prioritize recent vulnerabilities over backfill."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from dotenv import load_dotenv

from collectors.cisa_kev import CISAKEVCollector
from collectors.documents import ArxivCollector, FeedCollector, GitHubVendorAdvisoryCollector
from collectors.official_documents import FederalRegisterPolicyCollector, NISTStandardCollector
from incremental.api_collectors import GithubModifiedCollector, NVDModifiedCollector
from incremental.cursors import CursorStore
from incremental.engine import ingest_incremental_source
from monitoring.lock import AlreadyRunning, ProcessFileLock
from monitoring.service import atomic_json, utc_now
from monitoring.source_registry import get_source, get_sources
from storage.document_store import SQLiteDocumentStore
from storage.sqlite_store import SQLiteIntelligenceStore


def ensure_source_baseline(store, spec):
    with store._connect() as con:
        con.execute('''CREATE TABLE IF NOT EXISTS source_observation_baselines (
            source TEXT PRIMARY KEY, source_category TEXT NOT NULL, started_at TEXT NOT NULL)''')
        con.execute('''INSERT OR IGNORE INTO source_observation_baselines VALUES (?,?,?)''',
                    (spec.name, spec.category, utc_now()))


def _integer(name, default, minimum=0):
    value = int(os.getenv(name, str(default)))
    if value < minimum:
        raise ValueError(f'{name} must be >= {minimum}')
    return value


def document_collector(spec, now):
    options = dict(spec.options)
    if spec.kind == 'nist':
        options.pop('ai_only', None)
        return NISTStandardCollector(source=spec.name, url=spec.url, **options)
    if spec.kind == 'federal_register':
        options.pop('ai_only', None)
        return FederalRegisterPolicyCollector(source=spec.name, url=spec.url, **options)
    url = spec.url
    if spec.kind == 'arxiv':
        parts = urlsplit(url)
        query = parse_qs(parts.query)
        # Bound bootstrap volume; a rolling window also rechecks recent papers.
        # This covers new submissions, not all revisions of old papers.
        days = _integer('PAPER_LOOKBACK_DAYS', 7, 1)
        start = (now - timedelta(days=days)).strftime('%Y%m%d0000')
        end = now.strftime('%Y%m%d2359')
        terms = query.get('search_query', ['all:"AI security"'])[0]
        if 'submittedDate:' not in terms:
            query['search_query'] = [f'({terms}) AND submittedDate:[{start} TO {end}]']
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), ''))
    classes = {'feed': FeedCollector, 'arxiv': ArxivCollector, 'github_vendor': GitHubVendorAdvisoryCollector}
    return classes[spec.kind](spec.name, spec.category, spec.content_type or spec.category, url, **options)


def collect_source(spec, db_path, *, now=None, collector=None):
    """One independently retryable source; usable recent CVEs are stored first."""
    now = now or datetime.now(timezone.utc)
    db_path = Path(db_path).resolve()
    store = SQLiteIntelligenceStore(db_path)
    documents = SQLiteDocumentStore(db_path)
    ensure_source_baseline(store, spec)
    started = utc_now()
    try:
        fixed = {
            'nvd': ('NVD', 'https://services.nvd.nist.gov/rest/json/cves/2.0'),
            'github': ('GITHUB_ADVISORY', 'https://api.github.com/advisories'),
            'cisa': ('CISA_KEV', CISAKEVCollector.FEED_URL),
        }
        if spec.kind in fixed:
            name, url = fixed[spec.kind]
            if spec.name != name or (spec.url is not None and spec.url != url):
                raise ValueError('Core CVE adapters require their canonical name and official endpoint')
        if spec.kind in ('nvd', 'github'):
            if collector is None:
                cls = NVDModifiedCollector if spec.kind == 'nvd' else GithubModifiedCollector
                collector = cls(max_pages=_integer('RECENT_MAX_PAGES', 4, 1))
            settle = _integer('INCREMENTAL_SETTLE_MINUTES', 5)
            lookback = _integer('RECENT_LOOKBACK_HOURS', 12, 1)
            if settle >= min(360, lookback * 60):
                raise ValueError('Settlement must be below 6 hours and the recent lookback window')
            safe_end = now - timedelta(minutes=settle)
            # Publication must not wait behind bulk edits of old records.
            recent_method = getattr(collector, 'collect_published_window', collector.collect_window)
            recent = recent_method(now - timedelta(hours=lookback), safe_end)
            recent_counts = store.ingest_batch(spec.name, recent, started_at=started)
            # Catch-up has its own monotonic cursor. Failure cannot erase the
            # already committed recent phase or falsely advance its checkpoint.
            try:
                collector.max_pages = _integer('BACKFILL_MAX_PAGES', 4, 1)
                backlog = ingest_incremental_source(
                    name=spec.name, collector=collector, store=store,
                    cursors=CursorStore(db_path), now=now,
                    bootstrap_days=_integer('VULNERABILITY_BOOTSTRAP_DAYS', 7, 1),
                    overlap_minutes=_integer('INCREMENTAL_OVERLAP_MINUTES', 30),
                    settle_minutes=settle,
                    window_days=_integer('INCREMENTAL_WINDOW_DAYS', 7, 1),
                    window_hours=_integer('BACKFILL_WINDOW_HOURS', 1, 1),
                    max_windows=_integer('BACKFILL_MAX_WINDOWS', 1, 1),
                )
            except Exception as exc:
                store.record_failure(spec.name, safe_error(exc), started)
                return {'source': spec.name, 'category': spec.category, 'status': 'partial',
                        **recent_counts, 'recent_success': True, 'pending': True, 'error': safe_error(exc)}
            return {'source': spec.name, 'category': spec.category,
                    'status': 'partial' if backlog['pending'] else 'success',
                    **recent_counts, 'recent_success': True, 'pending': backlog['pending'], 'backfill': backlog}
        if spec.kind == 'cisa':
            collector = collector or CISAKEVCollector()
            rows = collector.collect()
            result = store.ingest_batch(spec.name, rows, started_at=started)
            result['endpoint_used'] = getattr(collector, 'endpoint_used', None)
        else:
            collector = collector or document_collector(spec, now)
            state = documents.get_http_state(spec.name) or {}
            batch = collector.collect(etag=state.get('etag'), last_modified=state.get('last_modified'))
            if batch.status not in ('success', 'not_modified'):
                raise ValueError('Source did not complete a valid collection')
            result = documents.ingest(spec.name, spec.category, batch.items, started_at=started)
            if batch.status == 'not_modified':
                etag = batch.etag if batch.etag is not None else state.get('etag')
                modified = batch.last_modified if batch.last_modified is not None else state.get('last_modified')
            else:
                etag, modified = batch.etag, batch.last_modified
            documents.save_http_state(spec.name, etag=etag, last_modified=modified)
            result['upstream_entries'] = batch.fetched_count
            result['http_status'] = batch.status
        return {'source': spec.name, 'category': spec.category, 'status': 'success', **result, 'pending': False}
    except Exception as exc:
        error = safe_error(exc)
        if spec.kind in ('nvd', 'github', 'cisa'):
            store.record_failure(spec.name, error, started)
        else:
            documents.record_failure(spec.name, spec.category, error, started_at=started)
        return {'source': spec.name, 'category': spec.category, 'status': 'failed', 'error': error}


def safe_error(exc):
    # Never echo request headers, full provider responses, or credential URLs.
    response = getattr(exc, 'response', None)
    status = getattr(response, 'status_code', None)
    return type(exc).__name__ + (f': HTTP {status}' if status else ': 请求或数据校验失败')


def _run_child(root, spec, db_path, config_path, timeout_seconds):
    result_path = None
    logs = db_path.parent / 'logs' / 'sources'
    logs.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
    log_path = logs / f'{spec.name}_{stamp}.log'
    started = utc_now()
    try:
        fd, temporary = tempfile.mkstemp(prefix='.source_result_', suffix='.json', dir=db_path.parent)
        os.close(fd)
        result_path = Path(temporary)
        args = [sys.executable, str(root / 'run_source.py'), '--source', spec.name,
                '--db', str(db_path), '--result', str(result_path)]
        if config_path:
            args.extend(['--config', str(Path(config_path).resolve())])
        env = os.environ.copy()
        env.update({'PYTHONIOENCODING': 'utf-8', 'PYTHONUTF8': '1'})
        with log_path.open('w', encoding='utf-8') as stream:
            completed = subprocess.run(args, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                       timeout=timeout_seconds, check=False)
        result = json.loads(result_path.read_text(encoding='utf-8'))
        if (not isinstance(result, dict) or result.get('source') != spec.name
                or result.get('status') not in {'success', 'partial', 'failed', 'skipped'}
                or (completed.returncode != 0 and result.get('status') != 'failed')):
            raise ValueError('Invalid child result/exit status')
        result['log_file'] = str(log_path)
        return result
    except Exception as exc:
        error = f'TimeoutError: 采集超过 {timeout_seconds} 秒，子进程已停止' if isinstance(exc, subprocess.TimeoutExpired) else safe_error(exc)
        if spec.kind in ('nvd', 'github', 'cisa'):
            SQLiteIntelligenceStore(db_path).record_failure(spec.name, error, started)
        else:
            SQLiteDocumentStore(db_path).record_failure(spec.name, spec.category, error, started_at=started)
        return {'source': spec.name, 'category': spec.category, 'status': 'failed', 'error': error, 'log_file': str(log_path)}
    finally:
        if result_path:
            result_path.unlink(missing_ok=True)


def run_cycle(root, *, db_path=None, config_path=None, workers=4, timeout_seconds=120,
              poll_interval_minutes=15, child_runner=None):
    root = Path(root).resolve()
    load_dotenv(root / '.env')
    db_path = Path(db_path or root / 'data' / 'intelligence.db').resolve()
    # Parent and source subprocesses have different working directories.
    # Forward the resolved catalog explicitly, including an environment catalog.
    config_path = config_path or os.getenv('INTELLIGENCE_SOURCE_CONFIG', '').strip() or None
    if config_path is not None:
        config_path = Path(config_path).resolve()
    sources = get_sources(config_path)
    if not sources or workers <= 0 or timeout_seconds <= 0:
        raise ValueError('At least one enabled source and positive worker/timeout limits are required')
    if ((len(sources) + workers - 1) // workers) * timeout_seconds + 90 >= 21600:
        raise ValueError('Worst-case source polling budget must be less than 6 hours')
    try:
        with ProcessFileLock(db_path.parent / '.monitoring.lock'):
            store = SQLiteIntelligenceStore(db_path)
            SQLiteDocumentStore(db_path)
            started = utc_now()
            for spec in sources:
                ensure_source_baseline(store, spec)
            baseline_file = db_path.parent / 'monitoring_baseline.json'
            if not baseline_file.exists():
                atomic_json(baseline_file, {'started_at': started})
            results = {}
            runner = child_runner or _run_child
            with ThreadPoolExecutor(max_workers=min(workers, len(sources))) as pool:
                futures = {pool.submit(runner, root, spec, db_path, config_path, timeout_seconds): spec for spec in sources}
                for future in as_completed(futures):
                    spec = futures[future]
                    try:
                        results[spec.name] = future.result()
                    except Exception as exc:
                        results[spec.name] = {'source': spec.name, 'category': spec.category,
                                              'status': 'failed', 'error': safe_error(exc)}
                    print(f"[SOURCE] {spec.name}: {results[spec.name]['status']}", flush=True)
            passed = sum(item['status'] == 'success' for item in results.values())
            failed = sum(item['status'] == 'failed' for item in results.values())
            status = 'success' if passed == len(sources) else 'failed' if failed == len(sources) else 'partial'
            result = {'status': status, 'started_at': started, 'finished_at': utc_now(),
                      'sources': results, 'configured_sources': len(sources),
                      'success_sources': passed, 'failed_sources': failed,
                      'pending_windows': any(item.get('pending', False) for item in results.values()),
                      'source_summary_complete': passed == len(sources), 'worker_count': workers,
                      'source_timeout_seconds': timeout_seconds,
                      'poll_interval_minutes': poll_interval_minutes}
            # Classification is independent of source latency and checkpoints.
            # Default budget is zero paid/model calls; rules can still complete.
            if child_runner is None and os.getenv('AUTO_CLASSIFY_V5', '1').lower() in {'1', 'true', 'yes'}:
                try:
                    args = [sys.executable, str(root / 'run_ai_classification_v5.py'), '--db', str(db_path),
                            '--max-items', str(_integer('CLASSIFY_V5_MAX_ITEMS', 300, 1)),
                            '--max-llm-calls', str(_integer('CLASSIFY_V5_MAX_LLM_CALLS', 0))]
                    with (db_path.parent / 'classification.log').open('a', encoding='utf-8') as stream:
                        classified = subprocess.run(args, cwd=root, stdout=stream, stderr=subprocess.STDOUT,
                                                    timeout=90, check=False)
                    result['classification'] = {'return_code': classified.returncode}
                except Exception as exc:
                    result['classification'] = {'error': safe_error(exc)}
            atomic_json(db_path.parent / 'monitoring_status.json', result)
            return result
    except AlreadyRunning:
        return {'status': 'skipped', 'sources': {}}
