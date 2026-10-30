from app import app
from src import database
from src import email_alert


def test_settings_page_persists_recipient_used_by_email_alerts(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "settings.db"))
    database.initialize_database()
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
    monkeypatch.setenv("EMAIL_ADDRESS", "sender@example.com")
    monkeypatch.setenv("EMAIL_PASSWORD", "test-app-password")
    monkeypatch.setenv("TO_EMAIL", "fallback@example.com")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.net")
    monkeypatch.setenv("SMTP_PORT", "587")

    sent_messages = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            assert host == "smtp.example.net"
            assert port == 587
            assert timeout == 10

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            pass

        def starttls(self, context):
            assert context is not None
            pass

        def login(self, username, password):
            assert username == "sender@example.com"
            assert password == "test-app-password"

        def send_message(self, message):
            sent_messages.append(message)

    monkeypatch.setattr(email_alert.smtplib, "SMTP", FakeSMTP)

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True
            session["username"] = "analyst"

        response = client.post(
            "/settings",
            data={"alert_recipient": "security-team@example.org"},
        )

        assert response.status_code == 302
        assert database.get_app_setting("alert_recipient") == (
            "security-team@example.org"
        )

        test_response = client.post("/settings/test-email")

        page = client.get("/settings").get_data(as_text=True)

    assert test_response.status_code == 302
    assert sent_messages[0]["To"] == "security-team@example.org"
    assert "security-team@example.org" in page
    assert "Email alerts ready" in page


def test_invalid_email_recipient_is_rejected_without_saving(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "invalid.db"))
    database.initialize_database()
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True

        response = client.post(
            "/settings",
            data={"alert_recipient": "not-an-email"},
        )

    assert response.status_code == 400
    assert b"Enter a valid email address." in response.data
    assert database.get_app_setting("alert_recipient") is None


def test_test_email_skips_smtp_when_configuration_is_incomplete(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "missing-config.db"))
    database.initialize_database()
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
    monkeypatch.delenv("EMAIL_ADDRESS", raising=False)
    monkeypatch.delenv("EMAIL_PASSWORD", raising=False)
    monkeypatch.setenv("TO_EMAIL", "recipient@example.org")
    monkeypatch.setattr(
        email_alert.smtplib,
        "SMTP",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("SMTP must not be used without sender credentials")
        ),
    )

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True

        client.post(
            "/settings",
            data={"alert_recipient": "recipient@example.org"},
        )
        response = client.post("/settings/test-email", follow_redirects=True)

    assert response.status_code == 200
    assert b"Configure EMAIL_ADDRESS and EMAIL_PASSWORD in .env." in response.data


def test_blank_saved_recipient_falls_back_to_to_email(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "fallback.db"))
    database.initialize_database()
    database.set_app_setting("alert_recipient", " ")
    monkeypatch.setenv("TO_EMAIL", "fallback@example.org")

    assert email_alert.get_alert_recipient() == "fallback@example.org"


def test_invalid_smtp_port_disables_test_delivery(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "smtp-port.db"))
    database.initialize_database()
    monkeypatch.setenv("EMAIL_ADDRESS", "sender@example.com")
    monkeypatch.setenv("EMAIL_PASSWORD", "test-app-password")
    monkeypatch.setenv("SMTP_PORT", "not-a-port")
    monkeypatch.setenv("TO_EMAIL", "recipient@example.org")

    configuration = email_alert.get_email_configuration_status(
        "recipient@example.org"
    )

    assert not configuration["ready"]
    assert "SMTP_PORT must be an integer" in configuration["message"]


def test_settings_page_requires_authentication(monkeypatch):
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)

    with app.test_client() as client:
        response = client.get("/settings")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_test_email_route_requires_authentication(monkeypatch):
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)

    with app.test_client() as client:
        response = client.post("/settings/test-email")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
