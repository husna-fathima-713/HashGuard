import smtplib
from email.mime.text import MIMEText


EMAIL_ADDRESS = "your_email@gmail.com"
EMAIL_PASSWORD = "your_app_password"

TO_EMAIL = "your_email@gmail.com"


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