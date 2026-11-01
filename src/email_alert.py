"""SMTP email notification helpers for HashGuard security alerts."""

import logging
import re
import smtplib
import ssl

from email.mime.text import MIMEText

from src.config import get_config_value
from src.database import get_app_setting

ALERT_RECIPIENT_SETTING = "alert_recipient"
EMAIL_ADDRESS_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
logger = logging.getLogger(__name__)


def is_valid_email_address(address: str) -> bool:

    return (
        isinstance(address, str)
        and len(address) <= 254
        and EMAIL_ADDRESS_PATTERN.fullmatch(address) is not None
    )


def get_alert_recipient() -> str:

    saved_recipient = get_app_setting(ALERT_RECIPIENT_SETTING, "")

    return saved_recipient.strip() or str(get_config_value("TO_EMAIL", "")).strip()


def get_email_configuration_status(
    recipient: str | None = None,
) -> dict[str, bool | str]:

    sender = str(get_config_value("EMAIL_ADDRESS", "")).strip()
    password = str(get_config_value("EMAIL_PASSWORD", ""))
    smtp_host = str(get_config_value("SMTP_HOST", "smtp.gmail.com")).strip()
    configured_recipient = (
        get_alert_recipient() if recipient is None else recipient.strip()
    )
    errors = []

    if not sender or not password:

        errors.append("Configure EMAIL_ADDRESS and EMAIL_PASSWORD in .env.")

    if not configured_recipient:

        errors.append("Set an alert recipient in Settings or TO_EMAIL.")
    elif not is_valid_email_address(configured_recipient):

        errors.append("The alert recipient must be a valid email address.")

    if not smtp_host:

        errors.append("SMTP_HOST cannot be empty.")

    try:

        smtp_port = int(get_config_value("SMTP_PORT", 587))

    except ValueError:

        smtp_port = None
        errors.append("SMTP_PORT must be an integer between 1 and 65535.")

    if smtp_port is not None and not 1 <= smtp_port <= 65535:

        errors.append("SMTP_PORT must be an integer between 1 and 65535.")

    return {
        "sender_configured": bool(sender and password),
        "recipient_configured": bool(configured_recipient),
        "ready": not errors,
        "message": " ".join(errors),
    }


def send_email_alert(message: str) -> bool:

    recipient = get_alert_recipient()
    configuration = get_email_configuration_status(recipient)

    if not configuration["ready"]:

        logger.error(
            "Critical email alert was not sent: %s",
            configuration["message"],
        )
        return False

    sender = str(get_config_value("EMAIL_ADDRESS", "")).strip()
    password = str(get_config_value("EMAIL_PASSWORD", ""))
    smtp_host = str(get_config_value("SMTP_HOST", "smtp.gmail.com")).strip()
    smtp_port = int(get_config_value("SMTP_PORT", 587))

    msg = MIMEText(message, _charset="utf-8")
    msg["Subject"] = "HashGuard Critical Security Alert"
    msg["From"] = sender
    msg["To"] = recipient

    try:

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:

            server.starttls(context=ssl.create_default_context())
            server.login(sender, password)
            refused_recipients = server.send_message(msg)

        if refused_recipients:

            logger.error(
                "SMTP server refused the HashGuard alert recipient(s)."
            )
            return False

    except (OSError, smtplib.SMTPException):

        logger.exception("Failed to send HashGuard critical email alert.")
        return False

    logger.info("HashGuard critical email alert sent.")
    return True