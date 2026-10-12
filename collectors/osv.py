"""Shell facade — OSV implementation lives in intelligence/platform_bridge/osv.py.

Import and patch this module (``collectors.osv``) from tests / monitor_agent.
The file under intelligence/ is the source of truth; this module executes it
in-place so ``_post`` patches on ``collectors.osv`` keep working.
"""
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "intelligence" / "platform_bridge" / "osv.py"
exec(compile(_SRC.read_text(encoding="utf-8"), str(_SRC), "exec"), globals())
