.PHONY: install run test scan scan-insecure docker

install:
	pip install -r requirements.txt

run:
	uvicorn src.app.main:app --reload --host 127.0.0.1 --port 8000 --no-access-log --log-config config/logging.json --no-proxy-headers

test:
	pytest -q

scan:
	python -m src.ai_guard.scan --target . --output reports/devsecops-report.md

scan-insecure:
	python -m src.ai_guard.scan --target examples/insecure --output reports/insecure-report.md --fail-on high

docker:
	docker compose up --build
