.PHONY: install check api web
install:
	bash scripts/bootstrap.sh
check:
	uv run python scripts/run_checks.py
api:
	uv run uvicorn asca.api.main:create_app --factory --host 127.0.0.1 --port 8000 --reload
web:
	cd apps/web && npm run dev
