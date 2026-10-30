import json
import os
import sqlite3

import pytest

import app as app_module
from app import app, limiter
from src import database


@pytest.fixture
def temporary_app_database(tmp_path, monkeypatch):
    database_path = tmp_path / "security.db"
    monkeypatch.setattr(database, "DB_PATH", str(database_path))
    monkeypatch.setattr(app_module, "_initialized_database_path", None)
    database.initialize_database()
    return database_path


def test_favicon_is_public_and_served_as_svg():
    with app.test_client() as client:
        response = client.get("/favicon.svg")

    assert response.status_code == 200
    assert response.mimetype == "image/svg+xml"
    assert b"<svg" in response.data


def test_registration_allowed_uses_database_count(monkeypatch):
    monkeypatch.setenv("ALLOW_REGISTRATION", "false")
    monkeypatch.setattr(app_module, "count_users", lambda: 0)

    assert app_module.registration_allowed()

    monkeypatch.setattr(app_module, "count_users", lambda: 1)

    assert not app_module.registration_allowed()


def test_login_page_and_stylesheet_are_public(temporary_app_database):
    with app.test_client() as client:
        page_response = client.get("/login")
        stylesheet_response = client.get("/static/style.css")

    assert page_response.status_code == 200
    assert b"/static/style.css" in page_response.data
    assert stylesheet_response.status_code == 200
    assert b".auth-page" in stylesheet_response.data


def test_unauthenticated_history_request_redirects_to_login(
    temporary_app_database,
):
    with app.test_client() as client:
        response = client.get("/history")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_baseline_update_requires_post_and_csrf_token(
    temporary_app_database,
    monkeypatch,
):
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", True)

    with app.test_client() as client:
        get_response = client.get("/update-baseline")
        post_response = client.post("/update-baseline")

    assert get_response.status_code == 405
    assert post_response.status_code == 400


def test_register_is_forbidden_when_user_exists_and_registration_is_unset(
    temporary_app_database,
    monkeypatch,
):
    monkeypatch.delenv("ALLOW_REGISTRATION", raising=False)
    assert database.register_user("existing-user", "test-password")

    with app.test_client() as client:
        response = client.get("/register")

    assert response.status_code == 403


def test_duplicate_registration_still_reports_existing_username(
    temporary_app_database,
    monkeypatch,
):
    monkeypatch.setenv("ALLOW_REGISTRATION", "true")
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
    assert database.register_user("existing-user", "test-password")

    with app.test_client() as client:
        response = client.post(
            "/register",
            data={"username": "existing-user", "password": "another-password"},
        )

    assert response.status_code == 200
    assert b"Username already exists" in response.data


def test_registration_rejects_missing_credentials(
    temporary_app_database,
    monkeypatch,
):
    monkeypatch.setenv("ALLOW_REGISTRATION", "true")
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)

    with app.test_client() as client:
        response = client.post("/register", data={"username": "", "password": ""})

    assert response.status_code == 400
    assert b"Username and password are required." in response.data


def test_login_rejects_missing_credentials(
    temporary_app_database,
    monkeypatch,
):
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
    assert database.register_user("known-user", "test-password")

    with app.test_client() as client:
        response = client.post("/login", data={"username": "known-user"})

    assert response.status_code == 200
    assert b"Invalid Credentials" in response.data


def test_registration_database_error_is_logged_and_shown(
    temporary_app_database,
    monkeypatch,
    caplog,
):
    monkeypatch.setenv("ALLOW_REGISTRATION", "true")
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
    with sqlite3.connect(temporary_app_database) as connection:
        connection.execute("""
            CREATE TRIGGER reject_registration
            BEFORE INSERT ON users
            BEGIN
                SELECT RAISE(ABORT, 'registration backend failure');
            END
        """)

    with app.test_client() as client:
        response = client.post(
            "/register",
            data={"username": "new-user", "password": "test-password"},
        )

    assert response.status_code == 503
    assert b"Registration could not be completed" in response.data
    assert "Failed to register user due to a database integrity error." in caplog.text


def test_invalid_event_status_returns_bad_request(
    temporary_app_database,
    monkeypatch,
):
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True
        response = client.post(
            "/update-event-status/1",
            data={"status": "invalid"},
        )

    assert response.status_code == 400


def test_baseline_update_records_user_time_and_change_summary(
    temporary_app_database,
    monkeypatch,
):
    recorded_events = []
    monkeypatch.setattr(
        "app.create_baseline",
        lambda: {
            "added": ["added.txt"],
            "modified": ["modified.txt"],
            "removed": ["removed.txt"],
        },
    )
    monkeypatch.setattr(
        "app.write_log",
        lambda *event, **metadata: recorded_events.append((event, metadata)),
    )
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True
            session["username"] = "test-user"

        response = client.post("/update-baseline")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")
    assert len(recorded_events) == 1
    event, metadata = recorded_events[0]
    event_type, filename, severity = event
    assert severity == "LOW"
    assert event_type == "BASELINE UPDATED"
    assert filename == "baseline/hashes.json"
    assert metadata == {
        "user": "test-user",
        "actor": "test-user",
        "details": (
            "User: test-user; Added (1): added.txt; "
            "Modified (1): modified.txt; Removed (1): removed.txt"
        ),
    }


def test_history_displays_baseline_update_event(
    temporary_app_database,
    monkeypatch,
):
    monkeypatch.setattr(
        "app.get_all_events",
        lambda: [
            (
                "2026-10-30 08:00:00",
                "LOW",
                "BASELINE UPDATED",
                "baseline/hashes.json",
                "open",
                None,
                None,
                1,
                "test-user",
                "User: test-user; Added (0): none",
            )
        ],
    )

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True
        response = client.get("/history")

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "BASELINE UPDATED" in page
    assert "baseline/hashes.json" in page
    assert "test-user" in page
    assert "User: test-user; Added (0): none" in page


def test_all_routes_except_login_and_register_require_authentication(
    monkeypatch,
):
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
    paths = [
        ("/", "GET"),
        ("/logout", "POST"),
        ("/download-report", "GET"),
        ("/download-pdf", "GET"),
        ("/download-csv", "GET"),
        ("/update-baseline", "POST"),
        ("/history", "GET"),
        ("/search", "GET"),
        ("/filter", "GET"),
        ("/analytics", "GET"),
        ("/settings", "GET"),
        ("/settings/test-email", "POST"),
    ]

    with app.test_client() as client:
        for path, method in paths:
            response = client.open(path, method=method)
            assert response.status_code == 302, (path, response.status_code)
            assert response.headers["Location"].endswith("/login")


def test_session_cookie_security_flags_are_configured():
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    expected_secure = os.getenv("SESSION_COOKIE_SECURE", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    assert app.config["SESSION_COOKIE_SECURE"] is expected_secure


def test_known_example_secret_is_rejected(monkeypatch):
    monkeypatch.setattr(app_module, "DEBUG", False)
    monkeypatch.setenv("SECRET_KEY", "replace_with_a_long_random_secret")

    with pytest.raises(RuntimeError, match="must be replaced"):
        app_module._get_secret_key()


def test_login_rate_limit_on_sixth_post(
    temporary_app_database,
    monkeypatch,
):
    limiter.reset()
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)

    with app.test_client() as client:
        for _ in range(5):
            response = client.post(
                "/login",
                data={"username": "wrong", "password": "wrong"},
                environ_base={"REMOTE_ADDR": "192.0.2.64"},
            )
            assert response.status_code == 200

        response = client.post(
            "/login",
            data={"username": "wrong", "password": "wrong"},
            environ_base={"REMOTE_ADDR": "192.0.2.64"},
        )

    assert response.status_code == 429
    limiter.reset()


def test_register_rate_limit(temporary_app_database, monkeypatch):
    limiter.reset()
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
    monkeypatch.setattr("app.registration_allowed", lambda: True)
    monkeypatch.setattr("app.register_user", lambda username, password: False)

    with app.test_client() as client:
        for _ in range(5):
            response = client.post(
                "/register",
                data={"username": "test", "password": "test"},
                environ_base={"REMOTE_ADDR": "192.0.2.11"},
            )
            assert response.status_code == 200

        response = client.post(
            "/register",
            data={"username": "test", "password": "test"},
            environ_base={"REMOTE_ADDR": "192.0.2.11"},
        )

    assert response.status_code == 429
    limiter.reset()


def test_database_is_initialized_for_imported_app_requests(tmp_path, monkeypatch):
    database_path = tmp_path / "lazy-init.db"
    monkeypatch.setattr(database, "DB_PATH", str(database_path))

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True

        response = client.get("/history")

    assert response.status_code == 200
    assert database_path.exists()
    assert database.get_event_summary()["total_events"] == 0


def test_direct_json_report_download_runs_scan_and_uses_database(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "report.db"))
    database.initialize_database()
    database.save_event(
        "2026-10-30T08:00:00+00:00",
        "HIGH",
        "MODIFIED",
        "watched/config.ini",
    )
    monkeypatch.setattr("app.check_integrity", lambda: ["Integrity changed"])

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True

        response = client.get("/download-report")

    report = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert report["total_alerts"] == 1
    assert report["alerts"] == ["Integrity changed"]
    assert report["events"][0]["filename"] == "watched/config.ini"


def test_dashboard_renders_database_summary_and_latest_events(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "dashboard.db"))
    database.initialize_database()
    database.save_event(
        "2026-10-30T08:00:00+00:00",
        "HIGH",
        "MODIFIED",
        "watched/config.ini",
    )
    monkeypatch.setattr("app.check_integrity", lambda: [])
    monkeypatch.setattr(
        "app.get_most_targeted_file",
        lambda: ("watched/config.ini", 1),
    )

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True

        response = client.get("/")

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Total events" in page
    assert "watched/config.ini" in page
    assert "Recent events" in page


def test_dashboard_displays_integrity_scan_failure(
    temporary_app_database,
    monkeypatch,
    caplog,
):
    def failed_scan():
        raise FileNotFoundError("Watched directory is missing.")

    monkeypatch.setattr(app_module, "check_integrity", failed_scan)

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True
        response = client.get("/")

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Integrity scan failed" in page
    assert "No integrity changes detected" not in page
    assert "Dashboard integrity scan failed." in caplog.text


def test_report_download_returns_error_when_scan_fails(
    temporary_app_database,
    monkeypatch,
    caplog,
):
    def failed_scan():
        raise OSError("permission denied")

    monkeypatch.setattr(app_module, "check_integrity", failed_scan)

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True
        response = client.get("/download-report")

    assert response.status_code == 503
    assert b"Integrity scan failed" in response.data
    assert "JSON report integrity scan failed." in caplog.text


def test_analytics_renders_database_data_without_external_chart_library(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "analytics.db"))
    database.initialize_database()
    database.save_event(
        "2026-10-30T08:00:00+00:00",
        "CRITICAL",
        "MODIFIED",
        "watched/config.ini",
    )

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True

        response = client.get("/analytics")

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "1 CRITICAL events" in page
    assert "cdn.jsdelivr.net" not in page
