$ErrorActionPreference = "Stop"

python -m pytest --cov=src --cov=app --cov-report=term-missing -q
exit $LASTEXITCODE
