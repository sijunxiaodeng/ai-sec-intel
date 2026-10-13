"""Recoverable window-density failures, distinct from network/data failures."""


class WindowPageLimitExceeded(RuntimeError):
    """Split a complete time range; never acknowledge a truncated response."""
