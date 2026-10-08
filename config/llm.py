# OpenAI 兼容接口。DeepSeek、通义千问都走这里。

import json
import urllib.request

from config.settings import load_settings


def configured():
    data = load_settings()
    return bool(data.get("api_key") and data.get("base_url") and data.get("model"))


def chat(messages, timeout=60, max_tokens=768, response_format=None):
    data = load_settings()
    if not data.get("api_key"):
        raise RuntimeError("还没有填写大模型 API Key")
    url = data["base_url"].rstrip("/") + "/chat/completions"
    body = {
        "model": data["model"],
        "temperature": 0.1,
        "max_tokens": max_tokens,
        "messages": messages,
    }
    if response_format is not None:
        body["response_format"] = response_format
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
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("大模型返回了空回答")
    if choices[0].get("finish_reason") == "length":
        raise RuntimeError("大模型输出达到长度限制，回答可能不完整")
    return content.strip()
