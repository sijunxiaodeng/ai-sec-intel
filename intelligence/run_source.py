"""One source worker, isolated and bounded by the monitor parent."""
import argparse
from pathlib import Path

from dotenv import load_dotenv
from monitoring.lock import AlreadyRunning, ProcessFileLock
from monitoring.multisource import collect_source
from monitoring.service import atomic_json
from monitoring.source_registry import get_source


def main():
    root = Path(__file__).resolve().parent
    load_dotenv(root / '.env')
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--db', default=str(root / 'data' / 'intelligence.db'))
    parser.add_argument('--config')
    parser.add_argument('--result', required=True)
    args = parser.parse_args()
    spec = get_source(args.source, args.config)
    db_path = Path(args.db).resolve()
    try:
        with ProcessFileLock(db_path.parent / f'.source_{spec.name}.lock'):
            result = collect_source(spec, db_path)
    except AlreadyRunning:
        result = {'source': spec.name, 'category': spec.category, 'status': 'skipped'}
    atomic_json(Path(args.result), result)
    return 1 if result['status'] == 'failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
