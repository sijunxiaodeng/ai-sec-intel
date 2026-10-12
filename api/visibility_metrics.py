"""Display observed categories and latency without substituting source names or polling intervals."""

LIBRARY_CATEGORIES = {
    'academic': 'academic_paper', 'policy': 'policy_regulation',
    'standard': 'technical_standard', 'research': 'security_blog',
    'vendor': 'vendor_advisory',
}


def category_observation(coverage, library):
    categories = coverage.get('observed_ai_categories')
    if isinstance(categories, list):
        values = sorted({c for c in categories if isinstance(c, str) and c})
        return len(values), 'B 当前有效 AI 内容类别'
    count = coverage.get('observed_ai_category_count')
    if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
        return count, 'B 当前有效 AI 内容类别'
    categories = library.get('source_categories') or []
    values = {LIBRARY_CATEGORIES.get(c, c) for c in categories if isinstance(c, str) and c}
    return len(values), '资料库存档类别（不证明实时监测覆盖）'


def latency_observation(coverage, compatibility_count):
    count = coverage.get('live_precise_samples')
    if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
        return count, 'B 按来源首次入库统计；同一漏洞跨来源分别计数'
    return compatibility_count, '根库精确时间兼容计数；B 监测证据未取得'
