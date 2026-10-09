"""固定官方资料的更新监测；不声称发现了所有新标准或法规。"""

REFERENCE_SOURCES = (
    {"id": "cac_generative_interim", "name": "国家互联网信息办公室", "category": "policy", "parser": "fixed",
     "url": "https://www.cac.gov.cn/2023-07/13/c_1690898327029107.htm",
     "expected_title": "生成式人工智能服务管理暂行办法", "last_article": 24},
    {"id": "cac_content_labels", "name": "国家互联网信息办公室", "category": "policy", "parser": "fixed",
     "url": "https://www.cac.gov.cn/2025-03/14/c_1743654684782215.htm",
     "expected_title": "人工智能生成合成内容标识办法", "last_article": 14},
    {"id": "nist_genai_profile", "name": "NIST", "category": "standard", "parser": "fixed",
     "url": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf", "reference_format": "pdf",
     "expected_title": "Artificial Intelligence Risk Management Framework", "version": "NIST AI 600-1 (2024)",
     "reference_kind": "voluntary_risk_framework", "published_at": "2024-07-26"},
    {"id": "gbt_45654_catalog", "name": "国家标准全文公开系统", "category": "standard", "parser": "fixed",
     "url": "https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F67D3F376E0A0A0FF5317FB36B32A30A",
     "reference_format": "catalog", "expected_title": "GB/T 45654-2025", "reference_kind": "recommended_national_standard"},
)
