# 运维前门：默认一键起产品面 http://127.0.0.1:8023
# 详情见 DEPLOY.md

.DEFAULT_GOAL := help

.PHONY: help up down demo offline online smoke collect logs status \
	demo-up demo-down demo-smoke demo-collect \
	prod-actions prod-collector prod-down

help: ## 列出常用目标
	@printf '%s\n' \
		'AI 安全知识情报 — 运维入口（单端口 :8023）' \
		'' \
		'常用：' \
		'  make up          一键启动（默认离线演示；有 Docker 用 compose，否则本地）' \
		'  make down        停止本机由 up/demo 拉起的实例' \
		'  make demo        up + smoke 冒烟' \
		'  make offline     显式离线演示（同 up 默认）' \
		'  make online      联网演示（docker-compose.yml / 本地 embed）' \
		'  make smoke       健康与产品链路检查' \
		'  make collect     演示采集一轮（联网模式）' \
		'  make logs        跟随当前演示日志' \
		'  make status      探测 :8023 是否就绪' \
		'' \
		'正式数据（进阶，勿与演示同时起）：' \
		'  make prod-actions     Actions 快照消费（scripts/production-up.sh actions）' \
		'  make prod-collector   常驻采集机（scripts/production-up.sh collector）' \
		'  make prod-down        停止正式 compose（actions + production）' \
		'' \
		'端口：产品面仅 http://127.0.0.1:8023' \
		'数据：离线 → .demo/offline/ 或 Docker 卷 offline-demo-data；详见 DEPLOY.md'

up: ## 一键启动产品（默认离线）
	./scripts/demo-up.sh

down: ## 停止演示实例
	./scripts/demo-down.sh

demo: up smoke ## 启动并冒烟

offline: ## 显式离线演示
	DEMO_NETWORK=offline ./scripts/demo-up.sh

online: ## 联网演示（需上游可达）
	DEMO_NETWORK=online ./scripts/demo-up.sh

smoke: ## 冒烟检查
	./scripts/demo-smoke.sh

collect: ## 演示采集
	./scripts/demo-collect.sh

# 兼容旧目标名
demo-up: up
demo-down: down
demo-smoke: smoke
demo-collect: collect

logs: ## 跟随演示日志
	@./scripts/demo-logs.sh

status: ## 探测 :8023
	@./scripts/demo-status.sh

prod-actions: ## 正式：Actions 快照模式
	bash scripts/production-up.sh actions

prod-collector: ## 正式：常驻采集机模式
	bash scripts/production-up.sh collector

prod-down: ## 停止正式 compose 项目
	-docker compose -f docker-compose.actions.yml down
	-docker compose -f docker-compose.production.yml down
