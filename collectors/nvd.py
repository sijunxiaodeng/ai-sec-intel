"""Shell facade — NVD product stream is the intelligence module local DB.

Implementation of the optional legacy keyword HTTP path lives in
``intelligence/platform_bridge/nvd_legacy.py``. Import and patch this module
(``collectors.nvd``) from tests / monitor_agent; the facade executes the
canonical file so ``fetch_nvd`` patches on ``collectors.nvd`` keep working.

Product「一次监测」does not dual-fetch NVD when the local library is on
(see agents/monitor_agent + ROOT_NVD_ENABLED).
"""
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "intelligence" / "platform_bridge" / "nvd_legacy.py"
exec(compile(_SRC.read_text(encoding="utf-8"), str(_SRC), "exec"), globals())
