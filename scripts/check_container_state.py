"""CI probe: the non-root main container must write shared state and retain it after seeding."""
import argparse
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import sys
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'check'))
    args = parser.parse_args()
    if os.environ.get('CI_STATE_PROBE') != '1':
        raise RuntimeError('this probe only runs in the disposable CI stack')
    if hasattr(os, 'geteuid') and os.geteuid() != 10001:
        raise RuntimeError('main container must run as the shared non-root UID 10001')
    root = Path('/app/data')
    db = Path(os.environ['INTELLIGENCE_DB_PATH'])
    marker = root / '.ci-persistence-probe'
    if not db.is_file():
        raise RuntimeError('seed database is absent')
    from config.settings import LOCAL, load_settings, save_settings
    if LOCAL != root / 'model-settings.json':
        raise RuntimeError('model settings must use the persistent main-data mount')
    with closing(sqlite3.connect(db)) as con, con:
        if args.mode == 'prepare':
            token = uuid.uuid4().hex
            save_settings({'api_key': 'ci-state-fixture-' + token})
            marker.write_text(token, encoding='utf-8')
            con.execute('CREATE TABLE IF NOT EXISTS ci_persistence_probe (token TEXT PRIMARY KEY)')
            con.execute('INSERT INTO ci_persistence_probe VALUES (?)', (token,))
        else:
            token = marker.read_text(encoding='utf-8')
            assert load_settings()['api_key'] == 'ci-state-fixture-' + token, 'recreation lost model settings'
            assert con.execute('SELECT token FROM ci_persistence_probe WHERE token=?', (token,)).fetchone(), 're-seeding erased persisted state'
            con.execute('DROP TABLE ci_persistence_probe')
            marker.unlink()
    with urllib.request.urlopen('http://127.0.0.1:8023/api/overview', timeout=5) as response:
        assert response.status == 200
    print('Shared state write/persistence and overview check passed: ' + args.mode)


if __name__ == '__main__':
    main()
