"""Persistence for normalized security intelligence."""

__all__ = ["SQLiteIntelligenceStore"]


def __getattr__(name):
    # Importing only changefeed in the embedded app must not load collection
    # code, whose top-level collectors package belongs to the shell process.
    if name == "SQLiteIntelligenceStore":
        from .sqlite_store import SQLiteIntelligenceStore
        return SQLiteIntelligenceStore
    raise AttributeError(name)
