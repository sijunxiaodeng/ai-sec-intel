.PHONY: demo demo-up demo-down demo-smoke demo-collect

demo: demo-up demo-smoke

demo-up:
	./scripts/demo-up.sh

demo-down:
	./scripts/demo-down.sh

demo-smoke:
	./scripts/demo-smoke.sh

demo-collect:
	./scripts/demo-collect.sh
