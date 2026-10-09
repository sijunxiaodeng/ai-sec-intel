# 大模型配置只写在本机 config/local.json，不进仓库。

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / "config" / "local.json"

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
    LOCAL.parent.mkdir(exist_ok=True)
    LOCAL.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
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
