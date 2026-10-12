# 大模型配置只写在本机 config/local.json，不进仓库。

import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_configured_path = Path(os.environ.get("APP_SETTINGS_PATH") or ROOT / "config" / "local.json").expanduser()
LOCAL = _configured_path if _configured_path.is_absolute() else ROOT / _configured_path

DEFAULTS = {
    "base_url": "https://api.deepseek.com",
    "model": "deepseek-flash",
    "api_key": "",
}


def load_settings():
    data = dict(DEFAULTS)
    if LOCAL.exists():
        try:
            saved = json.loads(LOCAL.read_text(encoding="utf-8"))
        except ValueError:
            saved = {}
        if isinstance(saved, dict):
            for key in DEFAULTS:
                if saved.get(key) not in (None, ""):
                    data[key] = saved.get(key)
    return data


def save_settings(incoming):
    current = load_settings()
    for key in ("base_url", "model", "api_key"):
        if key not in incoming:
            continue
        value = incoming.get(key)
        if key == "api_key" and value in ("", None, "******"):
            continue
        current[key] = (value or "").strip()
    LOCAL.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=LOCAL.parent,
                                         prefix=LOCAL.name + ".", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(current, ensure_ascii=False, indent=2))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, LOCAL)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return current


def public_settings():
    data = load_settings()
    key = data.get("api_key") or ""
    return {
        "base_url": data.get("base_url") or "",
        "model": data.get("model") or "",
        "has_key": bool(key),
        "key_hint": ("已保存，末四位 " + key[-4:]) if len(key) >= 4 else ("已保存" if key else "未设置"),
    }
