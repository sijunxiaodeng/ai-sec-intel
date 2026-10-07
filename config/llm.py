# OpenAI 兼容接口。DeepSeek、通义千问都走这里。

import json
import urllib.request

from config.settings import load_settings


def configured():
    data = load_settings()
    return bool(data.get("api_key") and data.get("base_url") and data.get("model"))


def chat(messages, timeout=60):
    data = load_settings()
    if not data.get("api_key"):
        raise RuntimeError("还没有填写大模型 API Key")
    url = data["base_url"].rstrip("/") + "/chat/completions"
    body = {
        "model": data["model"],
        "temperature": 0.1,
        "messages": messages,
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + data["api_key"],
            "Content-Type": "application/json",
            "User-Agent": "ai-sec-intel-student",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    choices = payload.get("choices") or []
    if not choices:
        raise RuntimeError("大模型没有返回内容")
    message = choices[0].get("message") or {}
    return message.get("content") or ""
