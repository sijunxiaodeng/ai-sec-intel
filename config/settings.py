# 大模型配置只写在本机 config/local.json，不进仓库。

import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if os.environ.get("OFFLINE_DEMO") == "1":
    LOCAL = Path(os.environ.get("MAIN_DATA_DIR", ROOT / ".demo/offline/main-data")) / "model-settings.json"
else:
    _configured_path = Path(os.environ.get("APP_SETTINGS_PATH") or ROOT / "config" / "local.json").expanduser()
    LOCAL = _configured_path if _configured_path.is_absolute() else ROOT / _configured_path

DEFAULTS = {
    "base_url": "https://api.deepseek.com",
    "model": "deepseek-flash",
    "api_key": "",
    "model_reasoning_effort": "",
    "model_review_enabled": False,
    "model_review_max_calls": 2,
    "model_review_daily_max_calls": 20,
    "model_review_interval_seconds": 60,
    "model_review_timeout_seconds": 90,
    "reasoning_budget_seconds": 30,
}

_LIMITS = {"model_review_max_calls": (0, 10), "model_review_daily_max_calls": (0, 1000),
           "model_review_interval_seconds": (30, 3600), "model_review_timeout_seconds": (5, 300),
           "reasoning_budget_seconds": (5, 180)}


def _validated(key, value):
    if key == "model_reasoning_effort":
        if not isinstance(value, str) or value not in {"", "none", "low", "medium", "high"}:
            raise ValueError("model_reasoning_effort must be empty, none, low, medium, or high")
    elif key == "model_review_enabled":
        if type(value) is not bool:
            raise ValueError("model_review_enabled must be boolean")
    elif key in _LIMITS:
        low, high = _LIMITS[key]
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"{key} must be an integer between {low} and {high}")
    elif not isinstance(value, str):
        raise ValueError(f"{key} must be text")
    return value.strip() if isinstance(value, str) else value


def load_settings():
    data = dict(DEFAULTS)
    if LOCAL.exists():
        try:
            saved = json.loads(LOCAL.read_text(encoding="utf-8"))
        except ValueError:
            saved = {}
        if isinstance(saved, dict):
            for key in DEFAULTS:
                if key in saved and saved[key] is not None:
                    try:
                        data[key] = _validated(key, saved[key])
                    except ValueError:
                        pass
    return data


def save_settings(incoming):
    current = load_settings()
    for key in DEFAULTS:
        if key not in incoming:
            continue
        value = incoming.get(key)
        if key == "api_key" and value in ("", None, "******"):
            continue
        current[key] = _validated(key, value)
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
    from config.llm import configured
    data = load_settings()
    key = data.get("api_key") or ""
    return {
        "base_url": data.get("base_url") or "",
        "model": data.get("model") or "",
        "has_key": bool(key),
        "llm_ready": configured(),
        "key_hint": ("已保存，末四位 " + key[-4:]) if len(key) >= 4 else ("已保存" if key else "未设置"),
        **{key: data[key] for key in DEFAULTS if key not in {"base_url", "model", "api_key"}},
    }
