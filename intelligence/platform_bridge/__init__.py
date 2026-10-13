"""Platform-facing collectors for the main-app funnel (models.IntelligenceItem).

Ownership
---------
- ``collectors/`` (sibling) writes multi-source rows into ``intelligence.db``.
- ``platform_bridge/`` owns the OSV HTTP/parse path and the optional legacy NVD
  fallback that emit platform cards for ``agents/monitor_agent`` → KB upsert.
- Root ``collectors/{nvd,osv}.py`` are thin shell facades only — no second
  independent monitoring product.

Product path (embed): b_monitor fills the local DB → monitor reads local CVE +
OSV via this bridge → funnel merge. Do not add parallel NVD/OSV under root.
"""
