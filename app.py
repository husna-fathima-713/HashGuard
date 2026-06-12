from flask import (
    Flask,
    render_template,
    send_file,
    request,
    redirect,
    session
)

import json
import os
import csv

from src.monitor import check_integrity, create_baseline

from src.database import (
    initialize_database,
    get_all_events,
    get_event_statistics,
    get_most_targeted_file,
    search_events,
    filter_by_severity,
    register_user,
    verify_user
)

from src.pdf_report import generate_pdf_report

app = Flask(__name__)

app.secret_key = "hashguard_secret_key"


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")

        password = request.form.get("password")

        if verify_user(username, password):

            session["logged_in"] = True

            session["username"] = username

            return redirect("/")

        return render_template(
            "login.html",
            error="Invalid Credentials"
        )

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username")

        password = request.form.get("password")

        success = register_user(
            username,
            password
        )

        if success:

            return redirect("/login")

        return render_template(
            "register.html",
            error="Username already exists"
        )

    return render_template("register.html")


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


@app.route("/")
def dashboard():

    if not session.get("logged_in"):

        return redirect("/login")

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

    if not session.get("logged_in"):

        return redirect("/login")

    return send_file(
        "reports/security_report.json",
        as_attachment=True
    )


@app.route("/download-pdf")
def download_pdf():

    if not session.get("logged_in"):

        return redirect("/login")

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
        newline=""
    ) as csv_file:

        writer = csv.writer(csv_file)

        writer.writerow([
            "Timestamp",
            "Severity",
            "Event Type",
            "Filename"
        ])

        for event in events:

            writer.writerow(event)

    return send_file(
        csv_path,
        as_attachment=True
    )


@app.route("/update-baseline")
def update_baseline():

    if not session.get("logged_in"):

        return redirect("/login")

    create_baseline()

    return """
    <h2>Baseline Updated Successfully</h2>
    <a href="/">Return to Dashboard</a>
    """


@app.route("/history")
def history():

    if not session.get("logged_in"):

        return redirect("/login")

    events = get_all_events()

    return render_template(
        "history.html",
        events=events
    )


@app.route("/search")
def search():

    if not session.get("logged_in"):

        return redirect("/login")

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

    if not session.get("logged_in"):

        return redirect("/login")

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

    if not session.get("logged_in"):

        return redirect("/login")

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