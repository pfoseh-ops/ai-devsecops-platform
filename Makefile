.PHONY: install run test scan scan-insecure docker

install:
	pip install -r requirements.txt

run:
	uvicorn src.app.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest -q

scan:
	python -m src.ai_guard.scan --target . --output reports/devsecops-report.md

scan-insecure:
	python -m src.ai_guard.scan --target examples/insecure --output reports/insecure-report.md --fail-on high

docker:
	docker compose up --build
