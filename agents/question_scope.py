"""识别有限的提问范围；不把事实中的否定误当成省略字段指令。"""
import re
from rag.answer import TOPIC_WORDS


def positive_question(question):
    # 只处理句首/分句首明确的回答指令。保留“不要只…”和“不需要用户交互吗”等事实询问。
    directive = (r"(?:不要(?!只|仅)|不用(?:说明|列出|讨论|比较|介绍)|"
                 r"不(?:比较|讨论|列出|解释|介绍|回答|提及|展示|补充|判断|问))")
    return re.sub(r"(?:^|(?<=[，,。；;]))\s*(?:请)?" + directive + r"[^，,。；;？?\n]*", "", question or "").strip()


def topics(question):
    q = positive_question(question).lower()
    return {name for name, words in TOPIC_WORDS.items() if any(w in q for w in words)}


def policy_scope_only(question, documents):
    """只对明确的范围/施行摘录使用直接条款；其他政策问题保留原检索路径。"""
    if not documents or any(d["content_scope"] != "policy_articles" for d in documents.values()):
        return False
    q = positive_question(question)
    requested = r"适用范围|适用对象|适用情形|施行条款|施行日期|施行时间|生效时间|生效日期|什么时候施行|何时施行"
    if not re.search(requested, q): return False
    for doc in documents.values(): q = q.replace(doc["title"], "")
    q = re.sub(requested, "", q)
    q = re.sub(r"标识办法|管理暂行办法|暂行办法|管理办法|这两份政策|两份政策|这份政策|这些政策|两份办法|该办法|这个办法|各自", "", q)
    q = re.sub(r"请|帮我|仅|只|根据|分别|原文|摘录|说明|列出|告诉我|的|和|与|及|以及|是|什么|条文|内容|[\s，,。；;：:？?]", "", q)
    return not q


def compare_scores(question):
    return "cvss" in topics(question) and not re.search(r"(?:不要|不用|无需|不)(?:进行)?(?:排序|排名)", question)
