"""进程内有界会话；只用用户指定的实体解析追问，不把旧回答当证据。"""
from dataclasses import dataclass, field
import re
import threading
import time
import uuid

from rag.evidence import CVE
from rag.answer import TOPIC_WORDS


class SessionError(ValueError):
    pass


def resolve(question, pinned="", previous=()):
    explicit = list(dict.fromkeys(value.upper() for value in CVE.findall(question)))
    if explicit:
        return explicit, "使用本轮问题明确指定的编号" + ("；覆盖下拉选择" if pinned and pinned.upper() not in explicit else "")
    if pinned:
        return [pinned.upper()], "使用本轮下拉选择的编号"
    text = question.lower()
    product = re.search(r"\b(?:ollama|vllm|triton|torchserve|langchain|ray)\b", text)
    refers = any(word in text for word in ("这个漏洞", "该漏洞", "它", "它们", "这两个", "这三个", "哪个", "那", "上述", "刚才"))
    topic = any(word in text for words in TOPIC_WORDS.values() for word in words) or "资产" in text
    if previous and not product and (refers or topic):
        return list(previous), "沿用会话中最近一次明确的漏洞范围；证据重新检索"
    return [], "未指定漏洞范围"


@dataclass
class _Session:
    touched: float
    scope: list = field(default_factory=list)
    turns: list = field(default_factory=list)
    total: int = 0
    pending: int = 0
    lock: object = field(default_factory=threading.Lock)


class SessionStore:
    def __init__(self, capacity=100, ttl=7200, max_turns=10, clock=time.monotonic):
        self.capacity, self.ttl, self.max_turns, self.clock = capacity, ttl, max_turns, clock
        self.sessions = {}
        self.lock = threading.Lock()

    def run(self, question, pinned, session_id, answer_fn):
        if session_id and not re.fullmatch(r"[a-f0-9]{32}", session_id):
            raise SessionError("会话编号格式无效，请开始新会话")
        with self.lock:
            now = self.clock()
            for key, value in list(self.sessions.items()):
                if now - value.touched >= self.ttl and not value.pending:
                    del self.sessions[key]
            if session_id:
                session = self.sessions.get(session_id)
                if session is None:
                    raise SessionError("会话已过期或服务已重启，请开始新会话")
            else:
                if len(self.sessions) >= self.capacity:
                    raise SessionError("当前会话数量已达上限，请稍后重试")
                session_id = uuid.uuid4().hex
                session = self.sessions[session_id] = _Session(now)
            # 全局锁只做登记；同一会话请求按序执行，其他会话仍可运行。
            session.pending += 1
        session.lock.acquire()
        try:
            scope, notice = resolve(question, pinned, session.scope)
            if len(scope) > 4:
                result = self._empty("一次最多比较 4 条漏洞，请缩小范围。")
            elif not scope and any(word in question for word in ("它", "这个漏洞", "该漏洞", "那", "这两个", "哪个")):
                result = self._empty("无法确定你指的是哪条漏洞，请提供 CVE 编号或选择情报。")
            elif "资产" in question and len(scope) > 1:
                result = self._empty("资产匹配每次需要唯一的 CVE 编号，请指定其中一条漏洞。")
            else:
                result = answer_fn(question, cve_ids=scope)
            # 只承接本轮确认有证据的范围；未知编号不会让下一轮回到更旧的漏洞。
            session.scope = scope if result.get("evidence") or scope == session.scope else []
            session.total += 1
            session.turns.append({"turn": session.total, "question": question,
                                  "cve_ids": scope, "answer": result["answer"][:12000],
                                  "used_model": result["used_model"]})
            session.turns = session.turns[-self.max_turns:]
            result.update(session_id=session_id, turn=session.total, context={"cve_ids": scope, "notice": notice},
                          history=list(session.turns))
            return result
        finally:
            with self.lock:
                session.touched = self.clock()
                session.pending -= 1
            session.lock.release()

    @staticmethod
    def _empty(answer):
        return {"answer": answer, "evidence": [], "used_model": False,
                "verdict": {"passed": True, "notes": ["证据不足，未生成事实结论"]}, "steps": []}


sessions = SessionStore()
