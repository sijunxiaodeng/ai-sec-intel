"""Shell-side collection bridges — not a second monitoring product.

Layout
------
- ``nvd.py`` / ``osv.py`` — thin facades → ``intelligence/platform_bridge/``
- ``intelligence.py`` — read local multi-source CVE (embed / sidecar)
- ``team_documents.py`` / ``library.py`` — library sync bridges (C path)
- ``cursors.py`` — platform funnel watermarks for OSV / legacy NVD

Authoritative multi-source fetch + local DB write: ``intelligence/collectors``
+ ``intelligence/monitoring``. Do not add parallel NVD/OSV HTTP here.
"""
