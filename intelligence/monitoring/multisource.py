"""Isolate source failures and prioritize recent vulnerabilities over backfill."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from dotenv import load_dotenv

from collectors.cisa_kev import CISAKEVCollector
from collectors.osv import OSVCollector
from collectors.documents import ArxivCollector, FeedCollector, GitHubVendorAdvisoryCollector
from collectors.official_documents import FederalRegisterPolicyCollector, NISTStandardCollector
from collectors.http import RequestBudget
from incremental.api_collectors import GithubModifiedCollector, NVDModifiedCollector
from incremental.cursors import CursorStore
from incremental.cursors import iso_utc
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


def recover_publications(spec, collector, store, cursors, *, now, safe_end,
                         recent_start, recent_success, deadline, settle):
    """Recover a fixed publication range separately from modification history.

    A legacy database starts with a persisted seven-day lower bound (configurable
    through the existing bootstrap setting), NOT a claim about earlier coverage.
    Only complete, committed windows advance the independent published cursor.
    The latest window may bridge the final gap only after all older slices finish.
    """
    key = spec.name + ':published'
    anchor = cursors.bootstrap_start(key, safe_end - timedelta(
        days=_integer('VULNERABILITY_BOOTSTRAP_DAYS', 7, 1)))
    before = cursors.get(key)
    target = recent_start if recent_success else safe_end
    counts = dict(fetched=0, inserted=0, updated=0, unchanged=0)
    # Reserve at least half of the remaining network time for modified history.
    remaining = max(0, deadline - time.monotonic())
    collector.max_pages = _integer('PUBLICATION_RECOVERY_MAX_PAGES', 4, 1)
    collector.request_budget = RequestBudget(
        max_requests=_integer('PUBLICATION_RECOVERY_MAX_REQUESTS', 6, 1),
        deadline=time.monotonic() + min(remaining / 2,
                                      _integer('PUBLICATION_RECOVERY_BUDGET_SECONDS', 25, 1)),
    )

    def ingest(name, rows, **kwargs):
        result = store.ingest_batch(name, rows, **kwargs)
        for field in counts:
            counts[field] += int(result[field])
        return result

    try:
        if (before or anchor) < target:
            outcome = ingest_incremental_source(
                name=spec.name, cursor_name=key,
                collector=SimpleNamespace(collect_window=collector.collect_published_window,
                                          max_pages=collector.max_pages,
                                          page_size=getattr(collector, 'page_size', 100)),
                store=SimpleNamespace(ingest_batch=ingest), cursors=cursors,
                now=now, settle_minutes=settle, target_end=target, initial_start=anchor,
                overlap_minutes=0, window_hours=_integer('PUBLICATION_RECOVERY_WINDOW_HOURS', 6, 1),
                max_windows=_integer('PUBLICATION_RECOVERY_MAX_WINDOWS', 4, 1),
                max_attempts=_integer('PUBLICATION_RECOVERY_MAX_ATTEMPTS', 8, 1),
                adaptive_min_window_minutes=_integer('BACKFILL_MIN_WINDOW_MINUTES', 15, 1),
            )
        else:
            outcome = dict(counts, windows=0, attempts=0, pending_reason=None)
    except Exception as exc:
        outcome = dict(counts, pending_reason='source_failure', error=safe_error(exc))
    checkpoint = cursors.get(key)
    # A recent success never skips an older missing publication range.
    if recent_success and (checkpoint or anchor) >= recent_start:
        cursors.advance(key, safe_end)
        checkpoint = cursors.get(key)
    outcome.update(bootstrap_start_at=iso_utc(anchor),
                   coverage_scope='published_since_persisted_bootstrap_start',
                   cursor_start_at=iso_utc(before) if before else None,
                   cursor_end_at=iso_utc(checkpoint) if checkpoint else None,
                   target_end_at=iso_utc(safe_end),
                   lag_seconds=max(0, (safe_end - (checkpoint or anchor)).total_seconds()),
                   requests=collector.request_budget.requests)
    outcome['pending'] = outcome['lag_seconds'] > 0
    return outcome


def collect_source(spec, db_path, *, now=None, collector=None):
    """One independently retryable source; usable recent CVEs are stored first."""
    now = now or datetime.now(timezone.utc)
    source_started = time.monotonic()
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
            'osv': ('OSV', OSVCollector.QUERY_URL),
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
            safe_end = (now - timedelta(minutes=settle)).replace(microsecond=0)
            recent_start = now - timedelta(hours=lookback)
            source_seconds = _integer('VULNERABILITY_SOURCE_BUDGET_SECONDS', 100, 1)
            child_seconds = float(os.getenv('INTELLIGENCE_CHILD_TIMEOUT_SECONDS', '120'))
            if child_seconds <= 0:
                raise ValueError('Child timeout must be positive')
            # Leave room for SQLite's 30-second busy timeout and result-file
            # bookkeeping before the parent terminates this child process.
            network_seconds = min(source_seconds, max(child_seconds / 2, child_seconds - 35))
            deadline = source_started + network_seconds
            # Publication must not wait behind bulk edits of old records.
            recent_method = getattr(collector, 'collect_published_window', collector.collect_window)
            cursors = CursorStore(db_path)
            if callable(getattr(collector, 'collect_published_window', None)):
                # Fix the migration range before the first HTTP request, so a
                # killed/failed first cycle cannot slide it forward next time.
                cursors.bootstrap_start(spec.name + ':published', safe_end - timedelta(
                    days=_integer('VULNERABILITY_BOOTSTRAP_DAYS', 7, 1)))
            recent_counts = dict(fetched=0, inserted=0, updated=0, unchanged=0)
            recent_error = None
            try:
                collector.request_budget = RequestBudget(
                    max_requests=_integer('RECENT_MAX_REQUESTS', 6, 1),
                    deadline=min(deadline, time.monotonic() + _integer('RECENT_BUDGET_SECONDS', 35, 1)),
                )
                recent = recent_method(recent_start, safe_end)
                recent_counts = store.ingest_batch(spec.name, recent, started_at=started)
            except Exception as exc:
                recent_error = safe_error(exc)
            # Catch-up has its own monotonic cursor. Failure cannot erase the
            # already committed recent phase or falsely advance its checkpoint.
            # A publication failure must also not starve historical revisions.
            publication = None
            if callable(getattr(collector, 'collect_published_window', None)):
                publication = recover_publications(
                    spec, collector, store, cursors, now=now, safe_end=safe_end,
                    recent_start=recent_start, recent_success=recent_error is None,
                    deadline=deadline, settle=settle)
            initial_checkpoint = cursors.get(spec.name)
            try:
                collector.max_pages = _integer('BACKFILL_MAX_PAGES', 4, 1)
                collector.request_budget = RequestBudget(
                    max_requests=_integer('BACKFILL_MAX_REQUESTS', 12, 1), deadline=deadline,
                )
                backlog = ingest_incremental_source(
                    name=spec.name, collector=collector, store=store,
                    cursors=cursors, now=now,
                    bootstrap_days=_integer('VULNERABILITY_BOOTSTRAP_DAYS', 7, 1),
                    overlap_minutes=_integer('INCREMENTAL_OVERLAP_MINUTES', 30),
                    settle_minutes=settle,
                    window_days=_integer('INCREMENTAL_WINDOW_DAYS', 7, 1),
                    window_hours=_integer('BACKFILL_WINDOW_HOURS', 24, 1),
                    max_windows=_integer('BACKFILL_MAX_WINDOWS', 16, 1),
                    adaptive_min_window_minutes=_integer('BACKFILL_MIN_WINDOW_MINUTES', 15, 1),
                    max_attempts=_integer('BACKFILL_MAX_ATTEMPTS', 32, 1),
                )
            except Exception as exc:
                store.record_failure(spec.name, safe_error(exc), started)
                checkpoint = cursors.get(spec.name)
                progressed = checkpoint is not None and (initial_checkpoint is None or checkpoint > initial_checkpoint)
                progress = {'cursor_end_at': iso_utc(checkpoint) if checkpoint else None,
                            'cursor_start_at': iso_utc(initial_checkpoint) if initial_checkpoint else None,
                            'target_end_at': iso_utc(safe_end), 'pending': True,
                            'pending_reason': 'source_failure',
                            'lag_seconds': max(0, (safe_end - checkpoint).total_seconds()) if checkpoint else None}
                return {'source': spec.name, 'category': spec.category,
                        'status': 'partial' if recent_error is None or progressed else 'failed',
                        **recent_counts, 'recent_success': recent_error is None, 'pending': True,
                        'recent_error': recent_error, 'publication_recovery': publication,
                        'backfill': progress, 'error': safe_error(exc)}
            backlog['requests'] = collector.request_budget.requests
            if recent_error:
                store.record_failure(spec.name, recent_error, started)
            return {'source': spec.name, 'category': spec.category,
                    'status': 'partial' if backlog['pending'] or recent_error or (publication or {}).get('pending') else 'success',
                    **recent_counts, 'recent_success': recent_error is None,
                    'recent_error': recent_error, 'pending': backlog['pending'] or bool((publication or {}).get('pending')),
                    'publication_recovery': publication, 'backfill': backlog}
        if spec.kind in ('cisa', 'osv'):
            collector = collector or (CISAKEVCollector() if spec.kind == 'cisa' else OSVCollector(**spec.options))
            rows = collector.collect()
            advisory_documents = OSVCollector.documents(rows) if spec.kind == 'osv' else None
            result = store.ingest_batch(spec.name, rows, started_at=started)
            if advisory_documents is not None:
                result['documents'] = documents.ingest(spec.name, spec.category, advisory_documents,
                                                       started_at=started)
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
        if spec.kind in ('nvd', 'github', 'cisa', 'osv'):
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
        env.update({'PYTHONIOENCODING': 'utf-8', 'PYTHONUTF8': '1',
                    'INTELLIGENCE_CHILD_TIMEOUT_SECONDS': str(timeout_seconds)})
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
        if spec.kind in ('nvd', 'github', 'cisa', 'osv'):
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
