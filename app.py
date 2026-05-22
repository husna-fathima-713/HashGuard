from flask import Flask, render_template

from src.monitor import check_integrity


app = Flask(__name__)


@app.route("/")
def home():

    alerts = check_integrity()

    return render_template("index.html", alerts=alerts)


if __name__ == "__main__":

    app.run(debug=True)