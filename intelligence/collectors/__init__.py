"""Multi-source collectors that write the local intelligence.db.

This package (plus ``monitoring/multisource.py``) is the only acquisition
implementation for NVD / GHSA / KEV / vendor / RSS / papers / standards.
Platform OSV + legacy NVD fallback live in ``intelligence/platform_bridge/``.
Root ``collectors/`` must stay as shell facades / DB readers only.
"""
