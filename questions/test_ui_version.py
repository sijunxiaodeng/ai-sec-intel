import tempfile
import unittest
from pathlib import Path
from api.ui_version import web_version, versioned_html


class UiVersionTests(unittest.TestCase):
    def test_content_change_invalidates_all_asset_urls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'index.html').write_text(
                '<meta content="__WEB_VERSION__"><script src="/assets/app.js?v=old"></script>'
                '<link href="/assets/styles.css"><a href="https://example.org/">source</a>')
            script = root / 'app.js'
            script.write_text('old')
            original = web_version(root)
            script.write_text('new')
            version = web_version(root)
            self.assertNotEqual(version, original)
            html = versioned_html(root, version)
            self.assertNotIn('__WEB_VERSION__', html)
            self.assertNotIn('?v=old', html)
            self.assertEqual(html.count('?v=' + version), 2)
            self.assertIn('https://example.org/', html)

    def test_entrypoint_and_status_are_not_cached(self):
        from fastapi.testclient import TestClient
        from api.app import app
        # No lifespan workers needed for these read-only routes.
        client = TestClient(app)
        for path in ['/', '/api/version']:
            response = client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['cache-control'], 'no-store')
        version = client.get('/api/version').json()['web_version']
        self.assertIn(version, client.get('/').text)
        response = client.get('/assets/app.js?v=' + version)
        self.assertEqual(response.headers['cache-control'], 'no-cache, must-revalidate')
