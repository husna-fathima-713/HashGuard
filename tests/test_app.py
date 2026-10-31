import json
import sqlite3
import threading
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import app as app_module
from src.extensions import limiter
from src import database


app = None


@pytest.fixture(autouse=True)
def bind_app_instance(app_instance):
    global app
    app = app_instance


@pytest.fixture
def app_instance(app):
    return app


@pytest.fixture
def temporary_app_database(app, tmp_path, monkeypatch):
    database_path = tmp_path / "security.db"
    monkeypatch.setattr(database, "DB_PATH", str(database_path))
    app.config["DATABASE"] = str(database_path)
    database.initialize_database()
    return database_path


def test_favicon_is_public_and_served_as_svg():
    with app.test_client() as client:
        response = client.get("/favicon.svg")

    assert response.status_code == 200
    assert response.mimetype == "image/svg+xml"
    assert b"<svg" in response.data
    response.close()


def test_fresh_factory_boot_creates_runtime_state_without_baseline(tmp_path):
    state = tmp_path / "fresh-state"
    state.mkdir()
    watched = state / "watched"
    watched.mkdir()
    whitelist = state / "whitelist.json"
    whitelist.write_text('{"ignored_files": []}', encoding="utf-8")
    database_path = state / "database" / "fresh.db"
    logs_dir = state / "logs"
    config = {
        "SECRET_KEY": "fresh-install-secret",
        "BASELINE_HMAC_KEY": "fresh-install-baseline-key",
        "DATABASE": str(database_path),
        "LOGS_DIR": str(logs_dir),
        "REPORTS_DIR": str(state / "reports"),
        "SCAN_ROOT": str(watched),
        "WATCHED_FOLDER": str(watched),
        "BASELINE_FILE": str(state / "baseline" / "hashes.json"),
        "WHITELIST_FILE": str(whitelist),
        "SESSION_COOKIE_SECURE": False,
    }

    assert not database_path.parent.exists()
    assert not logs_dir.exists()
    assert not Path(config["BASELINE_FILE"]).exists()

    fresh_app = app_module.create_app(config)

    assert database_path.is_file()
    assert logs_dir.is_dir()
    assert not Path(config["BASELINE_FILE"]).exists()
    with fresh_app.test_client() as client:
        assert client.get("/login").status_code == 200


def test_mapping_paths_resolve_relative_to_hashguard_root(tmp_path):
    from src.config import AppConfig

    watched = tmp_path / "watched"
    watched.mkdir()
    (tmp_path / "whitelist.json").write_text(
        '{"ignored_files": []}',
        encoding="utf-8",
    )
    config = AppConfig.from_env(
        {
            "SECRET_KEY": "mapping-test-secret",
            "BASELINE_HMAC_KEY": "mapping-test-baseline-key",
            "HASHGUARD_ROOT": str(tmp_path),
            "SCAN_ROOT": "watched",
            "WATCHED_FOLDER": ".",
            "DATABASE_PATH": "database/security.db",
            "LOGS_DIR": "logs",
            "REPORTS_DIR": "reports",
            "BASELINE_FILE": "baseline/hashes.json",
            "WHITELIST_FILE": "whitelist.json",
        }
    )

    assert config.scan_root == watched
    assert config.watched_folder == watched
    assert config.database_path == tmp_path / "database" / "security.db"
    assert config.logs_dir == tmp_path / "logs"
    assert config.baseline_file == tmp_path / "baseline" / "hashes.json"


def test_default_whitelist_is_loaded_from_config_directory(tmp_path):
    from src.config import AppConfig

    watched = tmp_path / "watched"
    watched.mkdir()
    whitelist = tmp_path / "config" / "whitelist.json"
    whitelist.parent.mkdir()
    whitelist.write_text('{"ignored_files": []}', encoding="utf-8")

    config = AppConfig.from_env(
        {
            "SECRET_KEY": "config-test-secret",
            "BASELINE_HMAC_KEY": "config-test-baseline-key",
            "HASHGUARD_ROOT": str(tmp_path),
            "SCAN_ROOT": "watched",
        }
    )

    assert config.whitelist_file == whitelist


def test_register_first_user_blocks_second_then_login_and_logout(app):
    app.config["WTF_CSRF_ENABLED"] = False

    with app.test_client() as client:
        first = client.post(
            "/register",
            data={"username": "first-user", "password": "secure-password"},
        )
        second = client.post(
            "/register",
            data={"username": "second-user", "password": "secure-password"},
        )
        login = client.post(
            "/login",
            data={"username": "first-user", "password": "secure-password"},
        )
        dashboard = client.get("/")
        logout = client.post("/logout")
        after_logout = client.get("/")

    assert first.status_code == 302
    assert second.status_code == 403
    assert login.status_code == 302
    assert dashboard.status_code == 200
    assert logout.status_code == 302
    assert after_logout.status_code == 302
    assert database.count_users() == 1


def test_manual_scan_records_added_modified_and_deleted_events(app):
    app.config["WTF_CSRF_ENABLED"] = False
    watched = Path(app.config["WATCHED_FOLDER"])
    original = watched / "modified.txt"
    deleted = watched / "deleted.txt"
    original.write_text("before", encoding="utf-8")
    deleted.write_text("remove me", encoding="utf-8")

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True
            session["username"] = "analyst"
        baseline_response = client.post("/update-baseline")
        original.write_text("after", encoding="utf-8")
        deleted.unlink()
        (watched / "added.txt").write_text("new", encoding="utf-8")
        scan_response = client.post("/scan")
        history_response = client.get("/history")

    assert baseline_response.status_code == 302
    assert scan_response.status_code == 302
    assert history_response.status_code == 200
    assert "MODIFIED" in history_response.get_data(as_text=True)
    assert "DELETED" in history_response.get_data(as_text=True)
    assert "NEW FILE" in history_response.get_data(as_text=True)
    assert {event[2] for event in database.get_all_events()} >= {
        "MODIFIED",
        "DELETED",
        "NEW FILE",
    }


def test_registration_allowed_uses_database_count(monkeypatch):
    app.config["ALLOW_REGISTRATION"] = False
    monkeypatch.setattr(app_module, "count_users", lambda: 0)

    with app.app_context():
        assert app_module.registration_allowed()

    monkeypatch.setattr(app_module, "count_users", lambda: 1)

    with app.app_context():
        assert not app_module.registration_allowed()


def test_rate_limit_storage_uri_comes_from_app_configuration():
    assert app.config["RATELIMIT_STORAGE_URI"] == "memory://"


def test_concurrent_first_user_registration_creates_one_user(
    temporary_app_database,
):
    start = threading.Barrier(8)

    def register(index):
        start.wait()
        return database.register_first_user(
            f"concurrent-user-{index}",
            "test-password",
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(register, range(8)))

    assert sum(results) == 1
    assert database.count_users() == 1


def test_login_page_and_stylesheet_are_public(temporary_app_database):
    with app.test_client() as client:
        page_response = client.get("/login")
        stylesheet_response = client.get("/static/style.css")

    assert page_response.status_code == 200
    assert b"/static/style.css" in page_response.data
    assert stylesheet_response.status_code == 200
    assert b".auth-page" in stylesheet_response.data
    stylesheet_response.close()


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
    app.config["ALLOW_REGISTRATION"] = False
    assert database.register_user("existing-user", "test-password")

    with app.test_client() as client:
        response = client.get("/register")

    assert response.status_code == 403


def test_duplicate_registration_still_reports_existing_username(
    temporary_app_database,
    monkeypatch,
):
    app.config["ALLOW_REGISTRATION"] = True
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
    assert database.register_user("existing-user", "test-password")

    with app.test_client() as client:
        response = client.post(
            "/register",
            data={"username": "existing-user", "password": "another-password"},
        )

    assert response.status_code == 200
    assert b"Username already exists" in response.data


def test_first_user_registration_race_returns_registration_closed_response(
    temporary_app_database,
    monkeypatch,
):
    app.config["ALLOW_REGISTRATION"] = False
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
    monkeypatch.setattr(app_module, "registration_allowed", lambda: False)
    monkeypatch.setattr(app_module, "register_first_user", lambda *_args: False)

    with app.test_client() as client:
        expected = client.get("/register")
        monkeypatch.setattr(app_module, "registration_allowed", lambda: True)
        response = client.post(
            "/register",
            data={"username": "racing-user", "password": "test-password"},
        )

    assert response.status_code == expected.status_code == 403
    assert response.data == expected.data


def test_registration_rejects_missing_credentials(
    temporary_app_database,
    monkeypatch,
):
    app.config["ALLOW_REGISTRATION"] = True
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
    tmp_path,
):
    app.config["ALLOW_REGISTRATION"] = True
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
    with closing(sqlite3.connect(temporary_app_database)) as connection:
        with connection:

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
    log_text = (tmp_path / "logs" / "security.log").read_text(encoding="utf-8")
    assert "Failed to register user due to a database integrity error." in log_text


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
    assert app.config["SESSION_COOKIE_SECURE"] is False


@pytest.mark.parametrize(
    ("debug", "environment_value", "expected"),
    [
        (False, None, True),
        (True, None, False),
        (False, "false", False),
        (True, "true", True),
    ],
)
def test_session_cookie_secure_defaults_by_environment(
    monkeypatch,
    debug,
    environment_value,
    expected,
):
    from src.config import AppConfig

    monkeypatch.setenv("SECRET_KEY", "unit-test-secret")
    monkeypatch.setenv("BASELINE_HMAC_KEY", "unit-test-baseline-key")
    monkeypatch.setenv("FLASK_DEBUG", str(debug).lower())
    if environment_value is None:
        monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
    else:
        monkeypatch.setenv("SESSION_COOKIE_SECURE", environment_value)
    config = AppConfig.from_env()
    assert config.session_cookie_secure is expected


def test_known_example_secret_is_rejected(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "replace_with_a_long_random_secret")

    from src.config import AppConfig

    with pytest.raises(ValueError, match="must be replaced"):
        AppConfig.from_env()


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("SECRET_KEY", " ", "SECRET_KEY cannot contain only whitespace"),
        ("BASELINE_HMAC_KEY", " ", "BASELINE_HMAC_KEY must be set"),
    ],
)
def test_config_rejects_whitespace_secrets(key, value, message):
    from src.config import AppConfig

    config = {
        "SECRET_KEY": "valid-test-secret",
        "BASELINE_HMAC_KEY": "valid-test-baseline-key",
        key: value,
        "FLASK_DEBUG": "false",
    }

    with pytest.raises(ValueError, match=message):
        AppConfig.from_env(config)


def test_config_requires_secret_key_outside_debug_mode():
    from src.config import AppConfig

    with pytest.raises(ValueError, match="SECRET_KEY is required"):
        AppConfig.from_env(
            {
                "SECRET_KEY": "",
                "BASELINE_HMAC_KEY": "valid-test-baseline-key",
                "FLASK_DEBUG": "false",
            }
        )


def test_config_rejects_redis_storage_uri_without_host():
    from src.config import AppConfig

    with pytest.raises(ValueError, match="Redis URI with a host"):
        AppConfig.from_env(
            {
                "SECRET_KEY": "valid-test-secret",
                "BASELINE_HMAC_KEY": "valid-test-baseline-key",
                "RATELIMIT_STORAGE_URI": "redis://",
            }
        )


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
    app.config["ALLOW_REGISTRATION"] = True
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


def test_factory_initializes_database_for_requests(app):
    database_path = Path(app.config["DATABASE"])

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True

        response = client.get("/history")

    assert response.status_code == 200
    assert database_path.exists()
    assert database.get_event_summary()["total_events"] == 0


def test_direct_json_report_download_uses_database_without_scanning(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    database_path = tmp_path / "report.db"
    monkeypatch.setattr(database, "DB_PATH", str(database_path))
    app.config["DATABASE"] = str(database_path)
    database.initialize_database()
    database.save_event(
        "2026-10-30T08:00:00+00:00",
        "HIGH",
        "MODIFIED",
        "watched/config.ini",
    )
    monkeypatch.setattr(
        "app.check_integrity",
        lambda: pytest.fail("A GET report download must not trigger a scan"),
    )

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True

        response = client.get("/download-report")

    report = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert report["total_alerts"] == 1
    assert report["alerts"] == ["[HIGH] MODIFIED: watched/config.ini"]
    assert report["events"][0]["filename"] == "watched/config.ini"


def test_dashboard_renders_database_summary_and_latest_events(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    database_path = tmp_path / "dashboard.db"
    monkeypatch.setattr(database, "DB_PATH", str(database_path))
    app.config["DATABASE"] = str(database_path)
    database.initialize_database()
    database.save_event(
        "2026-10-30T08:00:00+00:00",
        "HIGH",
        "MODIFIED",
        "watched/config.ini",
    )
    monkeypatch.setattr(
        "app.check_integrity",
        lambda: pytest.fail("Dashboard GET must not trigger a scan"),
    )
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


def test_dashboard_is_read_only_when_scan_service_fails(
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
    assert "Run scan" in page
    assert "Integrity scan failed" not in page
    assert "watched directory is missing" not in caplog.text


def test_manual_scan_reports_failure(
    temporary_app_database,
    monkeypatch,
):
    app.config["WTF_CSRF_ENABLED"] = False
    def failed_scan():
        raise OSError("permission denied")

    monkeypatch.setattr(app_module, "check_integrity", failed_scan)

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True
        response = client.post("/scan")

    assert response.status_code == 302
    log_text = (Path(app.config["LOGS_DIR"]) / "security.log").read_text(
        encoding="utf-8",
    )
    assert "Manual integrity scan failed." in log_text


def test_analytics_renders_database_data_without_external_chart_library(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    database_path = tmp_path / "analytics.db"
    monkeypatch.setattr(database, "DB_PATH", str(database_path))
    app.config["DATABASE"] = str(database_path)
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
