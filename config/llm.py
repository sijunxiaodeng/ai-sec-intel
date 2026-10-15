# OpenAI 兼容接口。DeepSeek、通义千问都走这里。

import json
import ipaddress
import urllib.request
from urllib.parse import urlsplit

from config.settings import load_settings


def local_endpoint(base_url):
    try:
        host = urlsplit(base_url).hostname or ""
        return host.lower() == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _ready(data):
    try:
        endpoint = urlsplit(data.get("base_url") or "")
        endpoint.port  # Reject malformed/out-of-range ports before advertising readiness.
        valid = (bool(endpoint.hostname) and endpoint.scheme in {"http", "https"}
                 and not endpoint.username and not endpoint.password
                 and not endpoint.query and not endpoint.fragment)
        local = local_endpoint(data.get("base_url") or "")
        return bool(valid and data.get("model") and (local or endpoint.scheme == "https")
                    and (local or data.get("api_key")))
    except (ValueError, TypeError):
        return False


def configured():
    from config.offline import enabled
    if enabled():
        return False
    data = load_settings()
    return _ready(data)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("模型接口不允许重定向")


def chat(messages, timeout=60, max_tokens=768, response_format=None):
    from config.offline import enabled
    if enabled():
        raise RuntimeError("离线演示不调用在线模型")
    data = load_settings()
    if not _ready(data):
        raise RuntimeError("模型配置不完整：远程 HTTPS 接口需要密钥，本机回环接口可不填密钥")
    url = data["base_url"].rstrip("/") + "/chat/completions"
    body = {
        "model": data["model"],
        "temperature": 0.1,
        "max_tokens": max_tokens,
        "messages": messages,
    }
    if data.get("model_reasoning_effort"):
        body["reasoning_effort"] = data["model_reasoning_effort"]
    # 当前官方 DeepSeek 默认启用思考；字段问答先采用非思考模式，
    # 避免有限输出额度耗在推理而未生成完整 JSON。其他兼容服务不接收此参数。
    if urlsplit(data["base_url"]).hostname == "api.deepseek.com" and data["model"] in (
        "deepseek-flash", "deepseek-v4-pro", "deepseek-v4-flash", "deepseek-v4-flash-vision-exp"
    ):
        body["thinking"] = {"type": "disabled"}
    if response_format is not None:
        body["response_format"] = response_format
    headers = {"Content-Type": "application/json", "User-Agent": "ai-sec-intel-student"}
    if data.get("api_key"):
        headers["Authorization"] = "Bearer " + data["api_key"]
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
    )
    handlers = [_NoRedirect()]
    if local_endpoint(data["base_url"]):
        handlers.append(urllib.request.ProxyHandler({}))
    with urllib.request.build_opener(*handlers).open(request, timeout=timeout) as response:
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
