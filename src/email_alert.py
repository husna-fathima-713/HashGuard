import os
import smtplib

from dotenv import load_dotenv
from email.mime.text import MIMEText


load_dotenv()

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
TO_EMAIL = os.getenv("TO_EMAIL")


def send_email_alert(message):

    try:

        msg = MIMEText(message)

        msg["Subject"] = "HashGuard Critical Security Alert"
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = TO_EMAIL

        server = smtplib.SMTP("smtp.gmail.com", 587)

        server.starttls()

        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

        server.send_message(msg)

        server.quit()

        print("Critical email alert sent.")

    except Exception as e:

        print(f"Failed to send email alert: {e}")