from flask import (
    Flask,
    flash,
    render_template,
    send_file,
    request,
    redirect,
    session,
    url_for
)
import sqlite3
from apscheduler.schedulers.background import BackgroundScheduler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

import json
import os
import csv
import io
import secrets
from threading import Lock
from datetime import datetime, timezone

from src.monitor import check_integrity, create_baseline, write_log
from src.email_alert import (
    get_alert_recipient,
    get_email_configuration_status,
    is_valid_email_address,
    send_email_alert,
)
from src import database as database_module

from src.database import (
    initialize_database,
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
    verify_user,
    update_event_status
)

from src.pdf_report import generate_pdf_report

load_dotenv()

app = Flask(__name__)

DEBUG = os.getenv("FLASK_DEBUG", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on"
}

def _get_secret_key():

    secret_key = os.getenv("SECRET_KEY")

    if secret_key and secret_key.strip() == "replace_with_a_long_random_secret":

        raise RuntimeError(
            "SECRET_KEY must be replaced with a unique, random secret."
        )

    if not secret_key and not DEBUG:

        raise RuntimeError(
            "SECRET_KEY must be set when FLASK_DEBUG is false."
        )

    return secret_key or secrets.token_hex(32)


SECRET_KEY = _get_secret_key()

app.config.update(
    SECRET_KEY=SECRET_KEY,
    DEBUG=DEBUG,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv(
        "SESSION_COOKIE_SECURE",
        "false"
    ).strip().lower() in {"1", "true", "yes", "on"}
)

csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[]
)
scheduler = None
_database_initialization_lock = Lock()
_initialized_database_path = None


def _run_scheduled_scan():

    try:

        with app.app_context():

            check_integrity()

    except Exception:

        app.logger.exception("Scheduled integrity scan failed")


def start_background_scanner():

    global scheduler

    if DEBUG and os.getenv("WERKZEUG_RUN_MAIN") != "true":

        return None

    if scheduler is not None and scheduler.running:

        return scheduler

    try:

        interval_seconds = int(os.getenv("SCAN_INTERVAL_SECONDS", "300"))

    except ValueError as error:

        raise ValueError(
            "SCAN_INTERVAL_SECONDS must be a positive integer."
        ) from error

    if interval_seconds <= 0:

        raise ValueError("SCAN_INTERVAL_SECONDS must be a positive integer.")

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        _run_scheduled_scan,
        "interval",
        seconds=interval_seconds,
        id="hashguard-integrity-scan",
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )
    scheduler.start()

    return scheduler


@app.before_request
def require_authentication():

    if request.endpoint in {
        "login",
        "register",
        "favicon",
        "static",
        None
    }:

        return None

    if not session.get("logged_in"):

        return redirect("/login")


@app.before_request
def ensure_database_initialized():

    global _initialized_database_path

    if request.endpoint in {"static", "favicon", None}:

        return None

    database_path = os.path.abspath(os.fspath(database_module.DB_PATH))

    if _initialized_database_path == database_path:

        return None

    with _database_initialization_lock:

        if _initialized_database_path != database_path:

            initialize_database()
            _initialized_database_path = database_path

    return None





@app.route("/favicon.svg")
def favicon():

    return send_file(
        os.path.join(app.root_path, "static", "favicon.svg"),
        mimetype="image/svg+xml"
    )


def registration_allowed():

    env_value = os.getenv("ALLOW_REGISTRATION", "false")

    if str(env_value).strip().lower() in {"1", "true", "yes", "on"}:

        return True

    return count_users() == 0


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():

    show_register_link = registration_allowed()

    if request.method == "POST":

        username = request.form.get("username")

        password = request.form.get("password")

        if username and password and verify_user(username, password):

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


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def register():

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

            success = register_user(
                username,
                password
            )

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


@app.route("/logout", methods=["POST"])
def logout():

    if not session.get("logged_in"):

        return redirect("/login")

    session.clear()

    return redirect("/login")


@app.route("/")
def dashboard():

    if not session.get("logged_in"):

        return redirect("/login")

    scan_error = None

    try:

        alerts = check_integrity()

    except OSError:

        app.logger.exception("Dashboard integrity scan failed.")
        alerts = []
        scan_error = (
            "Integrity scan failed. Check the watched directory and its "
            "permissions; no scan results are available."
        )

    events = get_all_events()

    return render_template(
        "index.html",
        alerts=alerts,
        scan_error=scan_error,
        summary=get_event_summary(),
        top_file=get_most_targeted_file(),
        recent_events=events[:8]
    )


def _build_report_data(alerts, events=None):

    if events is None:

        events = get_all_events()

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


def _save_security_report(report_data):

    os.makedirs("reports", exist_ok=True)
    report_path = os.path.join("reports", "security_report.json")

    with open(report_path, "w", encoding="utf-8") as report:

        json.dump(report_data, report, indent=4, ensure_ascii=False)

    return report_path


@app.route("/download-report")
def download_report():

    if not session.get("logged_in"):

        return redirect("/login")

    try:

        alerts = check_integrity()

    except OSError:

        app.logger.exception("JSON report integrity scan failed.")
        return "Integrity scan failed; report was not generated.", 503

    report_data = _build_report_data(alerts)
    _save_security_report(report_data)

    return send_file(
        io.BytesIO(
            json.dumps(report_data, indent=4, ensure_ascii=False).encode("utf-8")
        ),
        as_attachment=True,
        download_name="security_report.json",
        mimetype="application/json"
    )


@app.route("/download-pdf")
def download_pdf():

    if not session.get("logged_in"):

        return redirect("/login")

    stats = get_event_statistics()

    top_file = get_most_targeted_file()
    events = get_all_events()

    os.makedirs("reports", exist_ok=True)
    pdf_path = "reports/HashGuard_Security_Report.pdf"

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


@app.route("/download-csv")
def download_csv():

    if not session.get("logged_in"):

        return redirect("/login")

    events = get_all_events()

    os.makedirs("reports", exist_ok=True)

    csv_path = "reports/security_events.csv"

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


def _spreadsheet_safe_csv_value(value):

    if not isinstance(value, str):

        return value

    if (
        value.startswith(("\t", "\r", "\n"))
        or value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@"))
    ):

        return "'" + value

    return value


@app.route("/update-baseline", methods=["POST"])
def update_baseline():

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

    except OSError:

        app.logger.exception("Baseline update failed.")
        flash(
            "Baseline update failed. Check filesystem permissions and server logs.",
            "error"
        )
        return redirect(url_for("dashboard"))

    flash("Baseline updated and audit event recorded.", "success")

    return redirect(url_for("dashboard"))


@app.route("/history")
def history():

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


@app.route("/search")
def search():

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


@app.route("/filter")
def filter_events():

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


@app.route("/update-event-status/<int:event_id>", methods=["POST"])
def update_security_event_status(event_id):

    status = request.form.get("status", "")

    if status not in {
        "open",
        "acknowledged",
        "resolved",
        "false_positive"
    }:

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
        "history",
        filename=request.args.get("filename", ""),
        severity=request.args.get("severity", ""),
        status=request.args.get("status", "")
    ))


@app.route("/analytics")
def analytics():

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


@app.route("/settings", methods=["GET", "POST"])
def settings():

    if request.method == "POST":

        recipient = request.form.get("alert_recipient", "").strip()

        if recipient and not is_valid_email_address(recipient):

            return render_template(
                "settings.html",
                alert_recipient=recipient,
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

        return redirect(url_for("settings"))

    recipient = get_alert_recipient()

    return render_template(
        "settings.html",
        alert_recipient=recipient,
        **get_email_configuration_status(recipient),
    )


@app.route("/settings/test-email", methods=["POST"])
@limiter.limit("3 per hour", methods=["POST"])
def test_email_settings():

    recipient = get_alert_recipient()

    if not is_valid_email_address(recipient):

        flash(
            "Save a valid alert recipient before sending a test email.",
            "error",
        )
        return redirect(url_for("settings"))

    configuration = get_email_configuration_status(recipient)

    if not configuration["ready"]:

        flash(configuration["message"], "error")
        return redirect(url_for("settings"))

    if send_email_alert("This is a HashGuard email delivery test."):

        flash(f"Test email sent to {recipient}.", "success")

    else:

        flash(
            "Test email could not be sent. Check the server logs and SMTP settings.",
            "error",
        )

    return redirect(url_for("settings"))


if __name__ == "__main__":

    initialize_database()
    start_background_scanner()

    app.run(debug=DEBUG)