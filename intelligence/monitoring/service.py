"""One-shot monitoring runner: lock, invoke V2, persist logs and run metadata."""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .lock import AlreadyRunning, ProcessFileLock


SOURCE_ORDER = ('NVD', 'GITHUB_ADVISORY', 'CISA_KEV')
SOURCE_START_RE = re.compile(r'>>> 开始增量采集 (NVD|GITHUB_ADVISORY)')


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def atomic_json(path: Path, payload: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.monitoring_', suffix='.json', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def parse_source_results(text: str) -> tuple[dict, bool, bool]:
    """Parse existing V2 *printed* summaries; never assume a missing source passed."""
    results: dict[str, dict] = {}
    current = None
    summary_success = None
    summary_failed = None
    backlog = False
    for line in text.splitlines():
        found = SOURCE_START_RE.search(line)
        if found:
            current = found.group(1)
        if '>>> 同步 CISA KEV 全量目录快照' in line:
            current = 'CISA_KEV'
        if line.startswith('增量采集结果:') and current in SOURCE_ORDER:
            try:
                parsed = ast.literal_eval(line.partition(':')[2].strip())
                if isinstance(parsed, dict):
                    results[current] = parsed
                    backlog |= bool(parsed.get('pending'))
            except (ValueError, SyntaxError):
                pass
        if line.startswith('CISA 快照去重结果:'):
            try:
                parsed = ast.literal_eval(line.partition(':')[2].strip())
                if isinstance(parsed, dict):
                    results['CISA_KEV'] = parsed
            except (ValueError, SyntaxError):
                pass
        if line.startswith('ERROR '):
            for source in SOURCE_ORDER:
                if line.startswith(f'ERROR {source}:'):
                    results[source] = {'error': line}
        match = re.search(r'>>> 成功来源\s+(\d+)，失败来源\s+(\d+)', line)
        if match:
            summary_success, summary_failed = map(int, match.groups())
    valid_summary = summary_success == 3 and summary_failed == 0
    return results, bool(valid_summary and len(results) == 3), backlog




def _optional_run_classification(root: Path, emit, interpreter: str) -> None:
    """Run V5.1 when enabled; otherwise preserve the original optional V4 path.

    Neither a classification failure nor a missing classification script changes
    the collector's already-written status or checkpoints.
    """
    from dotenv import load_dotenv

    load_dotenv(root / ".env")

    def enabled(name: str) -> bool:
        return os.getenv(name, "0").strip().lower() in ("1", "true", "yes")

    use_v5 = enabled("AUTO_CLASSIFY_V5")
    use_v4 = enabled("AUTO_CLASSIFY_V4")
    if not use_v5 and not use_v4:
        return

    if use_v5:
        # Never invoke two classification workers for one monitoring run.
        if use_v4:
            emit("[CLASSIFY] V4 和 V5 均已开启：优先 V5.1，本轮不运行 V4。")
        name = "V5.1"
        script_name = "run_ai_classification_v5.py"
        max_items = os.getenv("CLASSIFY_V5_MAX_ITEMS", "100")
        max_llm_calls = os.getenv("CLASSIFY_V5_MAX_LLM_CALLS", "2")
    else:
        name = "V4"
        script_name = "run_ai_classification_v4.py"
        max_items = os.getenv("CLASSIFY_V4_MAX_ITEMS", "40")
        max_llm_calls = os.getenv("CLASSIFY_V4_MAX_LLM_CALLS", "3")

    script = root / script_name
    if not script.is_file():
        emit(f"[CLASSIFY] 已选择 {name} 但未找到 {script_name}；本轮不运行分类，采集状态不受影响。")
        return

    args = [
        interpreter, "-u", str(script),
        "--max-items", max_items,
        "--max-llm-calls", max_llm_calls,
    ]
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    emit(f"[CLASSIFY] 开始 {name} 增量分类（与采集事务独立；max_items={max_items}，max_llm_calls={max_llm_calls}）")
    try:
        completed = subprocess.run(
            args, cwd=str(root), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            timeout=600, check=False,
        )
        for line in (completed.stdout or "").splitlines():
            emit("[CLASSIFY] " + line)
        emit(f"[CLASSIFY] {name} 独立任务退出码={completed.returncode}")
        if completed.returncode != 0:
            emit("[CLASSIFY] 分类失败；采集检查点与监测成功状态保持不变，下次可独立重试。")
    except Exception as exc:
        emit(f"[CLASSIFY] {name} 分类任务异常: {type(exc).__name__}: {exc}")
        emit("[CLASSIFY] 采集状态不受影响；请检查 data/classification_status.json。")


def run_once(root: Path, python_executable: str | None = None, script_name='run_incremental_v2.py') -> dict:
    root = Path(root).resolve()
    interpreter = python_executable or sys.executable
    script = root / script_name
    logs_dir = root / 'logs' / 'monitoring'
    data_dir = root / 'data'
    lock_file = data_dir / '.monitoring.lock'
    status_file = data_dir / 'monitoring_status.json'

    try:
        with ProcessFileLock(lock_file):
            started = utc_now()
            stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
            logs_dir.mkdir(parents=True, exist_ok=True)
            log_file = logs_dir / f'monitor_{stamp}.log'
            output_lines = []
            exit_code = None
            error = None
            with log_file.open('w', encoding='utf-8', newline='\n') as stream:
                def emit(msg):
                    print(msg, flush=True)
                    stream.write(msg + '\n')
                    stream.flush()
                emit(f'[MONITOR] START={started}')
                emit(f'[MONITOR] Python={interpreter}')
                emit(f'[MONITOR] Script={script.name}')
                if not script.is_file():
                    error = f'找不到 {script.name}；请先把脚本放到项目根目录'
                    emit(f'[MONITOR] ERROR: {error}')
                    exit_code = 2
                else:
                    try:
                        cmd = [interpreter, '-u', str(script), '--source', 'all']
                        # Windows launches redirected Python stdout with the active
                        # ANSI code page (often GBK/cp936).  Decoding that as UTF-8
                        # corrupts Chinese source-summary markers (锟斤拷), making a
                        # successful run appear failed. Force the *child* to emit
                        # UTF-8, rather than relying on the scheduler's code page.
                        child_env = os.environ.copy()
                        child_env['PYTHONIOENCODING'] = 'utf-8'
                        child_env['PYTHONUTF8'] = '1'
                        proc = subprocess.Popen(
                            cmd, cwd=str(root), stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            encoding='utf-8', errors='replace', bufsize=1,
                            env=child_env,
                        )
                        assert proc.stdout is not None
                        for raw in proc.stdout:
                            line = raw.rstrip('\r\n')
                            output_lines.append(line)
                            emit(line)
                        exit_code = proc.wait()
                    except Exception as exc:
                        error = f'{type(exc).__name__}: {exc}'
                        exit_code = 2
                        emit(f'[MONITOR] ERROR: {error}')

                source_results, summary_ok, backlog = parse_source_results('\n'.join(output_lines))
                if exit_code == 0 and summary_ok:
                    status = 'partial' if backlog else 'success'
                else:
                    status = 'failed'
                finished = utc_now()
                result = {
                    'status': status,
                    'started_at': started,
                    'finished_at': finished,
                    'return_code': exit_code,
                    'sources': source_results,
                    'pending_windows': backlog,
                    'source_summary_complete': summary_ok,
                    'log_file': str(log_file),
                    'error': error,
                }
                emit(f'[MONITOR] FINISH={finished}; status={status}; exit_code={exit_code}')
                atomic_json(status_file, result)
                if status in ('success', 'partial'):
                    _optional_run_classification(root, emit, interpreter)
                return result
    except AlreadyRunning:
        print('[MONITOR] 已有一次监测运行中。本次安全跳过，未修改检查点和状态文件。', flush=True)
        return {'status': 'skipped', 'return_code': 0}
