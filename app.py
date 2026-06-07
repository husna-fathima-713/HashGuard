from flask import Flask, render_template, send_file, request
import json
import os

from src.monitor import check_integrity, create_baseline

from src.database import (
    initialize_database,
    get_all_events,
    get_event_statistics,
    get_most_targeted_file,
    search_events,
    filter_by_severity
)

from src.pdf_report import generate_pdf_report

app = Flask(__name__)


@app.route("/")
def dashboard():

    alerts = check_integrity()

    report_data = {
        "total_alerts": len(alerts),
        "alerts": alerts
    }

    os.makedirs("reports", exist_ok=True)

    with open(
        "reports/security_report.json",
        "w"
    ) as report:

        json.dump(report_data, report, indent=4)

    return render_template(
        "index.html",
        alerts=alerts
    )


@app.route("/download-report")
def download_report():

    return send_file(
        "reports/security_report.json",
        as_attachment=True
    )


@app.route("/download-pdf")
def download_pdf():

    stats = get_event_statistics()

    top_file = get_most_targeted_file()

    pdf_path = "reports/HashGuard_Security_Report.pdf"

    generate_pdf_report(
        pdf_path,
        stats,
        top_file
    )

    return send_file(
        pdf_path,
        as_attachment=True
    )


@app.route("/update-baseline")
def update_baseline():

    create_baseline()

    return """
    <h2>Baseline Updated Successfully</h2>
    <a href="/">Return to Dashboard</a>
    """


@app.route("/history")
def history():

    events = get_all_events()

    return render_template(
        "history.html",
        events=events
    )


@app.route("/search")
def search():

    filename = request.args.get(
        "filename",
        ""
    )

    events = search_events(filename)

    return render_template(
        "history.html",
        events=events
    )


@app.route("/filter")
def filter_events():

    severity = request.args.get(
        "severity",
        ""
    )

    events = filter_by_severity(severity)

    return render_template(
        "history.html",
        events=events
    )


@app.route("/analytics")
def analytics():

    stats = get_event_statistics()

    top_file = get_most_targeted_file()

    return render_template(
        "analytics.html",
        stats=stats,
        top_file=top_file
    )


if __name__ == "__main__":

    initialize_database()

    app.run(debug=True)