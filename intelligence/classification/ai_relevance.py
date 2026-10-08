import re
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class AIClassificationResult:
    is_ai_related: bool
    score: float
    category: str
    evidence: list[str] = field(default_factory=list)


class AIRelevanceClassifier:
    """
    AI安全相关性规则分类器 V2

    核心原则：
    1. 不再使用简单 substring 匹配
    2. AI项目实体优先于普通关键词
    3. package/product/vendor/title 权重大于 description
    4. ray / rag / agent 等泛化词不能单独判定 AI
    """

    # =========================================================
    # 一、明确的 AI 项目 / 产品实体
    # =========================================================
    STRONG_AI_CONCEPTS = {
        "prompt injection",
        "prompt leakage",
        "system prompt leakage",
        "model poisoning",
        "data poisoning",
        "retrieval augmented generation",
        "model context protocol",
        "mcp server",
        "mcp client",
    }
    AI_ENTITIES = {

        "ai_infrastructure": [
            "ollama",
            "vllm",
            "pytorch",
            "tensorflow",
            "onnxruntime",
            "tensorrt",
            "deepspeed",
            "triton inference server",
            "torchserve",
            "lmdeploy",
        ],

        "model_and_data": [
            "huggingface",
            "transformers",
            "sentence-transformers",
            "weaviate",
            "verba",
            "milvus",
            "qdrant",
            "chromadb",
            "chroma db",
        ],

        "ai_application_agent": [
            "langchain",
            "langgraph",
            "llamaindex",
            "langflow",
            "crewai",
            "autogen",
            "open webui",
            "modelcontextprotocol",
            "model context protocol",
            "knowns",
        ],

        "ai_supply_chain": [
            "safetensors",
            "model hub",
            "model repository",
            "model artifact",
        ],
    }

    # =========================================================
    # 二、语义概念
    # 这些词可以辅助判断，但不能像项目实体一样随便命中
    # =========================================================

    AI_CONCEPTS = {

        "ai_infrastructure": {
            "llm inference": 3,
            "model inference": 2,
            "inference server": 2,
            "model serving": 2,
            "gpu inference": 2,
        },

        "model_and_data": {
            "large language model": 3,
            "language model": 2,
            "machine learning model": 2,
            "deep learning model": 2,
            "embedding model": 2,
            "vector database": 3,

            "prompt injection": 3,
            "prompt leakage": 3,
            "system prompt leakage": 3,
            "model poisoning": 3,
            "data poisoning": 3,
        },

        "ai_application_agent": {
            "ai agent": 3,
            "llm agent": 3,
            "multi-agent": 3,
            "agentic ai": 3,

            "retrieval augmented generation": 3,
            "rag pipeline": 2,

            "mcp server": 3,
            "mcp client": 3,
            "model context protocol": 3,
        },

        "ai_supply_chain": {
            "model hub": 3,
            "model repository": 3,
            "model package": 2,
            "model artifact": 2,
        },
    }

    # =========================================================
    # 三、安全匹配函数
    # =========================================================

    @staticmethod
    def _contains_term(text, term):
        """
        使用边界匹配，避免：
        ray -> array
        verba -> verbatim
        rag -> fragment
        """

        if not text or not term:
            return False

        pattern = (
            r"(?<![A-Za-z0-9_])"
            + re.escape(term.lower())
            + r"(?![A-Za-z0-9_])"
        )

        return bool(
            re.search(
                pattern,
                text.lower()
            )
        )

    # =========================================================
    # 四、项目实体识别
    # =========================================================

    def _find_entity_hits(
        self,
        title,
        description,
        vendor,
        product,
        package_names,
    ):

        scores = defaultdict(int)
        evidence = defaultdict(list)

        # -----------------------------------------
        # 结构化字段：权重最高
        # -----------------------------------------

        structured_texts = [
            ("vendor", vendor),
            ("product", product),
        ]

        for package in package_names:
            structured_texts.append(
                ("package", package)
            )

        # -----------------------------------------
        # 遍历AI项目实体
        # -----------------------------------------

        for category, entities in self.AI_ENTITIES.items():

            for entity in entities:

                # package/vendor/product：
                # 命中说明非常强

                for field_name, text in structured_texts:

                    if self._contains_term(
                        text,
                        entity
                    ):

                        scores[category] += 5

                        evidence[category].append(
                            f"{field_name}:{entity}"
                        )

                # title：
                # 同样比较可信

                if self._contains_term(
                    title,
                    entity
                ):

                    scores[category] += 4

                    evidence[category].append(
                        f"title:{entity}"
                    )

                # description：
                # 权重低一点

                if self._contains_term(
                    description,
                    entity
                ):

                    scores[category] += 2

                    evidence[category].append(
                        f"description:{entity}"
                    )

        return scores, evidence

    # =========================================================
    # 五、AI概念识别
    # =========================================================

    def _find_concept_hits(
            self,
            title,
            description,
    ):

        text = " ".join([
            title or "",
            description or "",
        ])

        scores = defaultdict(int)
        evidence = defaultdict(list)

        for category, concepts in self.AI_CONCEPTS.items():

            for concept, weight in concepts.items():

                if self._contains_term(
                        text,
                        concept
                ):
                    scores[category] += weight

                    evidence[category].append(
                        f"concept:{concept}"
                    )

        return scores, evidence

    # =========================================================
    # 六、主分类函数
    # =========================================================

    def classify(
        self,
        title="",
        description="",
        vendor="",
        product="",
        package_names=None,
    ) -> AIClassificationResult:

        if package_names is None:
            package_names = []

        # =====================================================
        # 第一级：明确AI项目实体
        # =====================================================

        entity_scores, entity_evidence = (
            self._find_entity_hits(
                title=title,
                description=description,
                vendor=vendor,
                product=product,
                package_names=package_names,
            )
        )

        if entity_scores:

            best_category = max(
                entity_scores,
                key=entity_scores.get
            )

            score_value = (
                entity_scores[best_category]
            )

            # 有结构化实体命中时通常得分 >= 4/5
            if score_value >= 5:
                relevance = 1.0
            else:
                relevance = 0.8

            return AIClassificationResult(
                is_ai_related=True,
                score=relevance,
                category=best_category,
                evidence=list(
                    dict.fromkeys(
                        entity_evidence[
                            best_category
                        ]
                    )
                ),
            )

        # =====================================================
        # 第二级：AI语义概念
        # =====================================================

        concept_scores, concept_evidence = (
            self._find_concept_hits(
                title=title,
                description=description,
            )
        )

        if concept_scores:

            best_category = max(
                concept_scores,
                key=concept_scores.get
            )

            score_value = (
                concept_scores[best_category]
            )

            # 概念词要求更严格
            if score_value >= 5:

                relevance = 0.9
                is_ai_related = True


            elif score_value >= 3:

                relevance = 0.5

                is_ai_related = False

            elif score_value == 2:

                relevance = 0.4
                is_ai_related = False

            else:

                relevance = 0.2
                is_ai_related = False

            return AIClassificationResult(
                is_ai_related=is_ai_related,
                score=relevance,
                category=best_category,
                evidence=list(
                    dict.fromkeys(
                        concept_evidence[
                            best_category
                        ]
                    )
                ),
            )

        # =====================================================
        # 没有找到可靠AI证据
        # =====================================================

        return AIClassificationResult(
            is_ai_related=False,
            score=0.0,
            category="unknown",
            evidence=[],
        )