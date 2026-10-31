$ErrorActionPreference = "Stop"

ruff check .
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

python -m pytest -q
exit $LASTEXITCODE
