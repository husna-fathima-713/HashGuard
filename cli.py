"""Command-line scanner entrypoint for HashGuard."""

import argparse

from app import create_app
from src.monitor import check_integrity


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a HashGuard integrity scan.")
    parser.add_argument(
        "command",
        choices=("scan",),
        help="Run an integrity scan against the configured watched folder.",
    )
    parser.parse_args()

    app = create_app()
    with app.app_context():
        alerts = check_integrity()
        app.logger.info("CLI integrity scan completed with %d active alert(s)", len(alerts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
