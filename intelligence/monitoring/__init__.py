"""Monitor cycle orchestration for the local intelligence.db.

Owns source registry, locks, metrics, and ``multisource`` worker entrypoints.
Collectors themselves live in ``intelligence/collectors/``; platform OSV /
legacy NVD facades live in ``platform_bridge/``.
"""