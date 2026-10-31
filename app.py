"""Flask application routes and startup configuration for HashGuard."""

from flask import (
    Flask,
    Blueprint,
    current_app,
    flash,
    render_template,
    send_file,
    request,
    redirect,
    Response,
    session,
    url_for
)
import sqlite3
import json
import os
import csv
import io
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Mapping
from typing import TypeAlias

from src.monitor import (
    check_integrity,
    create_baseline,
    write_log,
)
from src.email_alert import (
    get_alert_recipient,
    get_email_configuration_status,
    is_valid_email_address,
    send_email_alert,
)
from src import database as database_module
from src.config import AppConfig, load_config
from src.event_status import EVENT_STATUSES, EventStatus
from src.extensions import csrf, limiter
from src.logging_setup import configure_app_logger, configure_logging
from src.scan_settings import get_scan_settings, save_scan_settings

from src.database import (
    get_all_events,
    get_event_statistics,
    get_event_summary,
    count_users,
    set_app_setting,
    clear_app_setting,
    get_most_targeted_file,
    search_events,
    filter_events as filter_event_records,
    register_user,
    register_first_user,
    verify_user,
    update_event_status
)

from src.pdf_report import generate_pdf_report

RouteResult: TypeAlias = str | Response | tuple[str, int]

web = Blueprint("web", __name__)


def create_app(config: AppConfig | Mapping[str, object] | None = None) -> Flask:
    app = Flask(__name__)
    app_config = load_config(config)
    app.config.from_mapping(app_config.to_flask_config())
    if isinstance(config, Mapping):
        extra_config = {
            key: value
            for key, value in config.items()
            if key not in app_config.to_flask_config()
        }
        app.config.update(extra_config)

    configure_logging(app.config["LOGS_DIR"])
    configure_app_logger(app)

    with app.app_context():
        database_module.initialize_database()

    limiter.init_app(app)
    csrf.init_app(app)
    app.before_request(require_authentication)
    app.extensions["hashguard.config"] = app_config

    with app.app_context():
        from src.monitor import validate_monitor_configuration

        validate_monitor_configuration()

    app.register_blueprint(web)
    app.context_processor(
        lambda: {"event_statuses": EVENT_STATUSES}
    )
    app.register_error_handler(500, _internal_server_error)
    return app


def _internal_server_error(error: Exception) -> tuple[str, int]:
    current_app.logger.error(
        "Unhandled application error",
        exc_info=(type(error), error, error.__traceback__),
    )
    return "An internal error occurred.", 500


def require_authentication() -> Response | None:

    if request.endpoint in {
        "web.login",
        "web.register",
        "web.favicon",
        "static",
        None
    }:

        return None

    if not session.get("logged_in"):

        return redirect("/login")


@web.route("/favicon.svg")
def favicon() -> Response:

    return send_file(
        os.path.join(current_app.root_path, "static", "favicon.svg"),
        mimetype="image/svg+xml"
    )


def registration_allowed() -> bool:

    if registration_is_unrestricted():

        return True

    return count_users() == 0


def registration_is_unrestricted() -> bool:

    return bool(current_app.config["ALLOW_REGISTRATION"])


@web.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login() -> RouteResult:

    show_register_link = registration_allowed()

    if request.method == "POST":

        username = request.form.get("username")

        password = request.form.get("password")

        if username and password and verify_user(username, password):

            session.clear()
            session["logged_in"] = True

            session["username"] = username

            return redirect("/")

        return render_template(
            "login.html",
            error="Invalid Credentials",
            show_register_link=show_register_link
        )

    return render_template(
        "login.html",
        show_register_link=show_register_link
    )


@web.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def register() -> RouteResult:

    if not registration_allowed():

        return render_template(
            "register.html",
            registration_disabled=True
        ), 403

    if request.method == "POST":

        username = request.form.get("username", "")

        password = request.form.get("password", "")

        if not username.strip() or not password:

            return render_template(
                "register.html",
                error="Username and password are required."
            ), 400

        try:

            if registration_is_unrestricted():

                success = register_user(username, password)

            else:

                success = register_first_user(username, password)

                if not success:

                    return render_template(
                        "register.html",
                        registration_disabled=True
                    ), 403

        except sqlite3.Error:

            return render_template(
                "register.html",
                error="Registration could not be completed. Please try again later."
            ), 503

        if success:

            flash("Your account is ready. Sign in to continue.", "success")
            return redirect("/login")

        return render_template(
            "register.html",
            error="Username already exists"
        )

    return render_template("register.html")


@web.route("/logout", methods=["POST"])
def logout() -> RouteResult:

    if not session.get("logged_in"):

        return redirect("/login")

    session.clear()

    return redirect("/login")


@web.route("/")
def dashboard() -> RouteResult:

    if not session.get("logged_in"):

        return redirect("/login")

    events = get_all_events()

    return render_template(
        "index.html",
        baseline_exists=Path(current_app.config["BASELINE_FILE"]).is_file(),
        summary=get_event_summary(),
        top_file=get_most_targeted_file(),
        recent_events=events[:8]
    )


@web.route("/scan", methods=["POST"])
@limiter.limit("5 per hour", methods=["POST"])
def scan_now() -> Response:
    try:
        alerts = check_integrity()
    except (OSError, ValueError):
        current_app.logger.exception("Manual integrity scan failed.")
        flash("Integrity scan failed. Check settings and server logs.", "error")
    else:
        flash(
            f"Integrity scan completed; {len(alerts)} finding(s) returned.",
            "success",
        )
    return redirect(url_for("web.dashboard"))


def _build_report_data(
    events: list[tuple[object, ...]] | None = None,
) -> dict[str, object]:

    if events is None:

        events = get_all_events()

    alerts = [
        f"[{event[1]}] {event[2]}: {event[3]}"
        for event in events
        if event[4] == EventStatus.OPEN.value
    ]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "alerts": alerts,
        "events": [
            {
                "id": event[7],
                "timestamp": event[0],
                "severity": event[1],
                "event_type": event[2],
                "filename": event[3],
                "status": event[4],
                "status_changed_by": event[5],
                "status_changed_at": event[6],
                "actor": event[8],
                "details": event[9]
            }
            for event in events
        ]
    }


@web.route("/download-report")
def download_report() -> RouteResult:

    if not session.get("logged_in"):

        return redirect("/login")

    report_data = _build_report_data()

    return send_file(
        io.BytesIO(
            json.dumps(report_data, indent=4, ensure_ascii=False).encode("utf-8")
        ),
        as_attachment=True,
        download_name="security_report.json",
        mimetype="application/json"
    )


@web.route("/download-pdf")
def download_pdf() -> Response:

    if not session.get("logged_in"):

        return redirect("/login")

    stats = get_event_statistics()

    top_file = get_most_targeted_file()
    events = get_all_events()

    reports_dir = current_app.config["REPORTS_DIR"]
    os.makedirs(reports_dir, exist_ok=True)
    pdf_path = os.path.join(reports_dir, "HashGuard_Security_Report.pdf")

    generate_pdf_report(
        pdf_path,
        stats,
        top_file,
        events
    )

    return send_file(
        os.path.abspath(pdf_path),
        as_attachment=True
    )


@web.route("/download-csv")
def download_csv() -> Response:

    if not session.get("logged_in"):

        return redirect("/login")

    events = get_all_events()

    reports_dir = current_app.config["REPORTS_DIR"]
    os.makedirs(reports_dir, exist_ok=True)
    csv_path = os.path.join(reports_dir, "security_events.csv")

    with open(
        csv_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        writer = csv.writer(csv_file)

        writer.writerow([
            "Timestamp",
            "Severity",
            "Event Type",
            "Filename",
            "Status",
            "Status Changed By",
            "Status Changed At",
            "Actor",
            "Details"
        ])

        for event in events:

            writer.writerow(
                _spreadsheet_safe_csv_value(value)
                for value in event[:7] + event[8:10]
            )

    return send_file(
        os.path.abspath(csv_path),
        as_attachment=True
    )


def _spreadsheet_safe_csv_value(value: object) -> object:

    if not isinstance(value, str):

        return value

    if (
        value.startswith(("\t", "\r", "\n"))
        or value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@"))
    ):

        return "'" + value

    return value


@web.route("/update-baseline", methods=["POST"])
@limiter.limit("5 per hour", methods=["POST"])
def update_baseline() -> Response:

    if not session.get("logged_in"):

        return redirect("/login")

    try:

        changes = create_baseline()
        username = session.get("username", "unknown")

        details = (
            f"User: {username}; "
            f"Added ({len(changes['added'])}): "
            f"{', '.join(changes['added']) or 'none'}; "
            f"Modified ({len(changes['modified'])}): "
            f"{', '.join(changes['modified']) or 'none'}; "
            f"Removed ({len(changes['removed'])}): "
            f"{', '.join(changes['removed']) or 'none'}"
        )

        write_log(
            "BASELINE UPDATED",
            "baseline/hashes.json",
            "LOW",
            user=username,
            actor=username,
            details=details
        )

    except (OSError, ValueError):

        current_app.logger.exception("Baseline update failed.")
        flash(
            "Baseline update failed. Check filesystem permissions and server logs.",
            "error"
        )
        return redirect(url_for("web.dashboard"))

    flash("Baseline updated and audit event recorded.", "success")

    return redirect(url_for("web.dashboard"))


@web.route("/history")
def history() -> RouteResult:

    if not session.get("logged_in"):

        return redirect("/login")

    filename = request.args.get("filename", "").strip()
    severity = request.args.get("severity", "").strip()
    status = request.args.get("status", "").strip()
    if filename or severity or status:

        events = filter_event_records(
            severity=severity or None,
            status=status or None,
            filename=filename or None
        )

    else:

        events = get_all_events()

    return render_template(
        "history.html",
        events=events,
        selected_filename=filename,
        selected_status=status,
        selected_severity=severity
    )


@web.route("/search")
def search() -> RouteResult:

    if not session.get("logged_in"):

        return redirect("/login")

    filename = request.args.get("filename", "").strip()
    status = request.args.get("status", "").strip()
    severity = request.args.get("severity", "").strip()
    events = search_events(
        filename,
        status=status or None,
        severity=severity or None
    )

    return render_template(
        "history.html",
        events=events,
        selected_filename=filename,
        selected_status=status,
        selected_severity=severity
    )


@web.route("/filter")
def filter_events() -> RouteResult:

    if not session.get("logged_in"):

        return redirect("/login")

    severity = request.args.get("severity", "")
    status = request.args.get("status", "")

    filename = request.args.get("filename", "").strip()
    events = filter_event_records(
        severity=severity or None,
        status=status or None,
        filename=filename or None
    )

    return render_template(
        "history.html",
        events=events,
        selected_filename=filename,
        selected_status=status,
        selected_severity=severity
    )


@web.route("/update-event-status/<int:event_id>", methods=["POST"])
@limiter.limit("30 per minute", methods=["POST"])
def update_security_event_status(event_id: int) -> RouteResult:

    status = request.form.get("status", "")

    if status not in EVENT_STATUSES:

        return "Invalid event status.", 400

    updated = update_event_status(
        event_id,
        status,
        session.get("username", "unknown"),
        datetime.now(timezone.utc).isoformat()
    )

    if not updated:

        return "Security event not found.", 404

    flash("Event status updated.", "success")

    return redirect(url_for(
        "web.history",
        filename=request.args.get("filename", ""),
        severity=request.args.get("severity", ""),
        status=request.args.get("status", "")
    ))


@web.route("/analytics")
def analytics() -> RouteResult:

    if not session.get("logged_in"):

        return redirect("/login")

    stats = get_event_statistics()

    top_file = get_most_targeted_file()
    maximum_count = max((count for _, count in stats), default=0)
    severity_stats = [
        {
            "severity": severity,
            "count": count,
            "percentage": round(count * 100 / maximum_count)
            if maximum_count
            else 0
        }
        for severity, count in stats
    ]

    return render_template(
        "analytics.html",
        stats=stats,
        severity_stats=severity_stats,
        summary=get_event_summary(),
        top_file=top_file
    )


@web.route("/settings", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def settings() -> RouteResult:

    if request.method == "POST":

        recipient = request.form.get("alert_recipient", "").strip()

        if recipient and not is_valid_email_address(recipient):

            interval, folder = get_scan_settings()
            return render_template(
                "settings.html",
                alert_recipient=recipient,
                scan_interval_seconds=interval,
                watched_folder=folder,
                email_error="Enter a valid email address.",
                **get_email_configuration_status(recipient),
            ), 400

        if recipient:

            set_app_setting("alert_recipient", recipient)
            flash(
                "Alert recipient saved. New critical alerts will use this address.",
                "success"
            )

        else:

            clear_app_setting("alert_recipient")
            flash(
                "Custom recipient cleared. HashGuard will use TO_EMAIL from .env, if configured.",
                "success"
            )

        return redirect(url_for("web.settings"))

    recipient = get_alert_recipient()
    interval, folder = get_scan_settings()

    return render_template(
        "settings.html",
        alert_recipient=recipient,
        scan_interval_seconds=interval,
        watched_folder=folder,
        **get_email_configuration_status(recipient),
    )


@web.route("/settings/scanning", methods=["POST"])
@limiter.limit("5 per hour", methods=["POST"])
def update_scan_settings() -> RouteResult:
    interval_value = request.form.get("scan_interval_seconds", "")
    folder_value = request.form.get("watched_folder", "").strip()
    try:
        interval, folder = save_scan_settings(interval_value, folder_value)
    except ValueError as error:
        recipient = get_alert_recipient()
        return render_template(
            "settings.html",
            alert_recipient=recipient,
            scan_interval_seconds=interval_value,
            watched_folder=folder_value,
            scan_error=str(error),
            email_error=None,
            **get_email_configuration_status(recipient),
        ), 400

    flash(
        "Scanning settings saved. The scheduler will apply them on its next run.",
        "success",
    )
    return redirect(url_for("web.settings"))


@web.route("/settings/test-email", methods=["POST"])
@limiter.limit("3 per hour", methods=["POST"])
def test_email_settings() -> Response:

    recipient = get_alert_recipient()

    if not is_valid_email_address(recipient):

        flash(
            "Save a valid alert recipient before sending a test email.",
            "error",
        )
        return redirect(url_for("web.settings"))

    configuration = get_email_configuration_status(recipient)

    if not configuration["ready"]:

        flash(configuration["message"], "error")
        return redirect(url_for("web.settings"))

    if send_email_alert("This is a HashGuard email delivery test."):

        flash(f"Test email sent to {recipient}.", "success")

    else:

        flash(
            "Test email could not be sent. Check the server logs and SMTP settings.",
            "error",
        )

    return redirect(url_for("web.settings"))


if __name__ == "__main__":

    create_app().run()