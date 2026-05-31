from flask import Flask, render_template, send_file
import json
import os

from src.monitor import check_integrity, create_baseline

app = Flask(__name__)


@app.route("/")
def dashboard():

    alerts = check_integrity()

    report_data = {
        "total_alerts": len(alerts),
        "alerts": alerts
    }

    os.makedirs("reports", exist_ok=True)

    report_path = "reports/security_report.json"

    with open(report_path, "w") as report:

        json.dump(report_data, report, indent=4)

    return render_template("index.html", alerts=alerts)


@app.route("/download-report")
def download_report():

    report_path = "reports/security_report.json"

    return send_file(report_path, as_attachment=True)


@app.route("/update-baseline")
def update_baseline():

    create_baseline()

    return """
    <h2>Baseline Updated Successfully</h2>
    <a href='/'>Return to Dashboard</a>
    """


if __name__ == "__main__":

    app.run(debug=True)