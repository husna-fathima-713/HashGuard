.PHONY: setup run scheduler scan test lint coverage check

setup:
	python -m pip install -r requirements.txt -r requirements-dev.txt

run:
	python app.py

scheduler:
	python scheduler_main.py

scan:
	python cli.py scan

test:
	python -m pytest -q

lint:
	ruff check .

coverage:
	python -m pytest --cov=src --cov=app --cov-report=term-missing -q

check: lint test
