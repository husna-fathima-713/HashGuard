from flask import Flask, render_template

from src.monitor import check_integrity

import threading
import time


app = Flask(__name__)

latest_alerts = []


def background_monitor():

    global latest_alerts

    while True:

        latest_alerts = check_integrity()

        time.sleep(5)


@app.route("/")
def home():

    return render_template("index.html", alerts=latest_alerts)


if __name__ == "__main__":

    monitor_thread = threading.Thread(target=background_monitor)

    monitor_thread.daemon = True

    monitor_thread.start()

    app.run(debug=True)