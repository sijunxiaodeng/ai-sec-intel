"""Explicit, repeatable re-fusion for databases created before evidence fixes."""
import argparse
import json
from pathlib import Path

from monitoring.lock import ProcessFileLock
from storage.sqlite_store import SQLiteIntelligenceStore


def main():
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description='用原始来源记录重新融合已有数据库；不联网')
    parser.add_argument('--db', default=str(root / 'data' / 'intelligence.db'))
    args = parser.parse_args()
    db = Path(args.db).resolve()
    if not db.is_file():
        parser.error('数据库不存在，请先采集；不会创建空数据库')
    with ProcessFileLock(db.parent / '.monitoring.lock'), ProcessFileLock(db.parent / '.ai_classification.lock'):
        result = SQLiteIntelligenceStore(db).rebuild_unified()
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
