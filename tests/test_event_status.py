import csv
import io
import sqlite3
from pathlib import Path

import pytest

from src import database


app = None


@pytest.fixture(autouse=True)
def bind_app_instance(app_instance):
    global app
    app = app_instance


@pytest.fixture
def app_instance(app):
    return app


def test_initialize_database_migrates_existing_events_table(tmp_path, monkeypatch):
    database_path = tmp_path / "existing.db"
    connection = sqlite3.connect(database_path)
    connection.execute("""
        CREATE TABLE security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            severity TEXT,
            event_type TEXT,
            filename TEXT
        )
    """)
    connection.execute("""
        INSERT INTO security_events
        (timestamp, severity, event_type, filename)
        VALUES (?, ?, ?, ?)
    """, ("2026-10-30 08:00:00", "HIGH", "MODIFIED", "file.txt"))
    connection.commit()
    connection.close()

    monkeypatch.setattr(database, "DB_PATH", str(database_path))

    database.initialize_database()

    events = database.get_all_events()
    assert events[0][:5] == (
        "2026-10-30 08:00:00",
        "HIGH",
        "MODIFIED",
        "file.txt",
        "open",
    )
    assert events[0][5:7] == (None, None)
    assert events[0][8:10] == (None, None)

    connection = sqlite3.connect(database_path)
    column_defaults = {
        row[1]: row[4]
        for row in connection.execute("PRAGMA table_info(security_events)")
    }
    connection.close()

    assert column_defaults["status"] == "'open'"
    assert column_defaults["status_changed_by"] == "NULL"
    assert column_defaults["status_changed_at"] == "NULL"
    assert column_defaults["actor"] == "NULL"
    assert column_defaults["details"] == "NULL"


def test_initialize_database_creates_configured_database_parent(
    tmp_path,
    monkeypatch,
):
    database_path = tmp_path / "new-directory" / "security.db"
    monkeypatch.setattr(database, "DB_PATH", str(database_path))

    database.initialize_database()

    assert database_path.is_file()


def test_count_users_returns_count_and_closes_connection(
    tmp_path,
    monkeypatch,
):
    database_path = tmp_path / "users.db"
    monkeypatch.setattr(database, "DB_PATH", str(database_path))
    database.initialize_database()
    database.register_user("analyst", "password")

    original_connect = sqlite3.connect
    connections = []

    class TrackedConnection:
        def __init__(self, path):
            self.connection = original_connect(path)
            self.closed = False
            connections.append(self)

        def cursor(self):
            return self.connection.cursor()

        def close(self):
            self.closed = True
            self.connection.close()

    monkeypatch.setattr(database.sqlite3, "connect", TrackedConnection)

    assert database.count_users() == 1
    assert connections[0].closed


def test_count_users_handles_database_without_users_table(
    tmp_path,
    monkeypatch,
):
    database_path = tmp_path / "no-users.db"
    sqlite3.connect(database_path).close()
    monkeypatch.setattr(database, "DB_PATH", str(database_path))

    assert database.count_users() == 0


def test_initialize_database_migrates_legacy_baseline_event(
    tmp_path,
    monkeypatch,
):
    database_path = tmp_path / "legacy-baseline.db"
    connection = sqlite3.connect(database_path)
    connection.execute("""
        CREATE TABLE security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            severity TEXT,
            event_type TEXT,
            filename TEXT
        )
    """)
    connection.execute("""
        INSERT INTO security_events
        (timestamp, severity, event_type, filename)
        VALUES (?, ?, ?, ?)
    """, (
        "2026-10-30 08:00:00",
        "LOW",
        "BASELINE UPDATED",
        "User: analyst; Added (1): new.txt",
    ))
    connection.commit()
    connection.close()

    monkeypatch.setattr(database, "DB_PATH", str(database_path))
    database.initialize_database()

    event = database.get_all_events()[0]
    assert event[3] == "baseline/hashes.json"
    assert event[8] == "analyst"
    assert event[9] == "User: analyst; Added (1): new.txt"


def test_baseline_updates_are_excluded_from_most_targeted_file(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "targeted.db"))
    database.initialize_database()
    database.save_event(
        "2026-10-30 08:00:00",
        "LOW",
        "BASELINE UPDATED",
        "baseline/hashes.json",
        actor="analyst",
    )
    database.save_event(
        "2026-10-30 08:01:00",
        "HIGH",
        "MODIFIED",
        "baseline/hashes.json",
    )

    assert database.get_most_targeted_file() == ("baseline/hashes.json", 1)


def test_save_event_persists_actor_and_details(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "actor.db"))
    database.initialize_database()

    database.save_event(
        "2026-10-30 08:00:00",
        "LOW",
        "BASELINE UPDATED",
        "baseline/hashes.json",
        actor="analyst",
        details="Added (1): new.txt",
    )

    event = database.get_all_events()[0]
    assert event[3] == "baseline/hashes.json"
    assert event[8:10] == ("analyst", "Added (1): new.txt")


def test_status_update_records_actor_timestamp_and_filters(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "events.db"))
    database.initialize_database()
    database.save_event(
        "2026-10-30 08:00:00",
        "HIGH",
        "MODIFIED",
        "file.txt",
    )

    assert database.update_event_status(
        1,
        "acknowledged",
        "analyst",
        "2026-10-30 08:10:00",
    )
    assert not database.update_event_status(
        999,
        "resolved",
        "analyst",
        "2026-10-30 08:11:00",
    )
    assert not database.update_event_status(
        1,
        "invalid",
        "analyst",
        "2026-10-30 08:12:00",
    )

    event = database.get_all_events()[0]
    assert event[4:7] == (
        "acknowledged",
        "analyst",
        "2026-10-30 08:10:00",
    )
    assert database.filter_events(status="acknowledged") == [event]
    assert database.filter_events(severity="HIGH", status="resolved") == []


def test_history_combines_filename_severity_and_status_filters(
    tmp_path,
    monkeypatch,
):
    database_path = tmp_path / "combined.db"
    monkeypatch.setattr(database, "DB_PATH", str(database_path))
    app.config["DATABASE"] = str(database_path)
    database.initialize_database()
    database.save_event(
        "2026-10-30T08:00:00+00:00",
        "HIGH",
        "MODIFIED",
        "watched/config.ini",
    )
    database.save_event(
        "2026-10-30T08:01:00+00:00",
        "LOW",
        "MODIFIED",
        "watched/config.ini",
    )
    database.save_event(
        "2026-10-30T08:02:00+00:00",
        "HIGH",
        "MODIFIED",
        "watched/other.ini",
    )

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True

        response = client.get(
            "/history?filename=config.ini&severity=HIGH&status=open"
        )

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "watched/config.ini" in page
    assert "watched/other.ini" not in page
    assert "Apply filters" in page


def test_status_update_route_requires_csrf_and_records_session_user(
    tmp_path,
    monkeypatch,
):
    database_path = tmp_path / "route.db"
    monkeypatch.setattr(database, "DB_PATH", str(database_path))
    app.config["DATABASE"] = str(database_path)
    database.initialize_database()
    database.save_event(
        "2026-10-30 08:00:00",
        "MEDIUM",
        "NEW FILE",
        "new.txt",
    )
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True
            session["username"] = "reviewer"

        response = client.post(
            "/update-event-status/1",
            data={"status": "resolved"},
        )

    assert response.status_code == 302
    event = database.get_all_events()[0]
    assert event[4] == "resolved"
    assert event[5] == "reviewer"
    assert event[6]


def test_csv_export_contains_status_and_change_metadata(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    database_path = tmp_path / "csv.db"
    monkeypatch.setattr(database, "DB_PATH", str(database_path))
    app.config["DATABASE"] = str(database_path)
    database.initialize_database()
    database.save_event(
        "2026-10-30 08:00:00",
        "HIGH",
        "MODIFIED",
        "file.txt",
    )
    database.update_event_status(
        1,
        "false_positive",
        "analyst",
        "2026-10-30 08:10:00",
    )

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True
        response = client.get("/download-csv")

    try:
        rows = list(csv.reader(io.StringIO(response.get_data(as_text=True))))
    finally:
        response.close()

    assert rows[0] == [
        "Timestamp",
        "Severity",
        "Event Type",
        "Filename",
        "Status",
        "Status Changed By",
        "Status Changed At",
        "Actor",
        "Details",
    ]
    assert rows[1][4:] == [
        "false_positive",
        "analyst",
        "2026-10-30 08:10:00",
        "",
        "",
    ]


def test_csv_export_neutralizes_spreadsheet_formulas(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    database_path = tmp_path / "csv-formula.db"
    monkeypatch.setattr(database, "DB_PATH", str(database_path))
    app.config["DATABASE"] = str(database_path)
    database.initialize_database()
    database.save_event(
        "2026-10-30 08:00:00",
        "HIGH",
        "MODIFIED",
        '=HYPERLINK("https://example.test","open")',
    )
    database.save_event(
        "2026-10-30 08:01:00",
        "HIGH",
        "MODIFIED",
        "  @SUM(1,1)",
    )
    database.save_event(
        "2026-10-30 08:02:00",
        "HIGH",
        "MODIFIED",
        "normal.txt",
    )

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True
        response = client.get("/download-csv")

    try:
        rows = list(csv.reader(io.StringIO(response.get_data(as_text=True))))
    finally:
        response.close()

    assert rows[1][3] == "normal.txt"
    assert rows[2][3] == "'  @SUM(1,1)"
    assert rows[3][3] == '\'=HYPERLINK("https://example.test","open")'


def test_json_and_pdf_routes_include_event_status(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    database_path = tmp_path / "exports.db"
    monkeypatch.setattr(database, "DB_PATH", str(database_path))
    app.config["DATABASE"] = str(database_path)
    database.initialize_database()
    database.save_event(
        "2026-10-30 08:00:00",
        "HIGH",
        "MODIFIED",
        "file.txt",
    )
    database.update_event_status(
        1,
        "resolved",
        "analyst",
        "2026-10-30 08:10:00",
    )
    monkeypatch.setattr("app.check_integrity", lambda: [])
    monkeypatch.setattr("app.get_event_statistics", lambda: [])
    monkeypatch.setattr("app.get_most_targeted_file", lambda: None)
    pdf_events = []

    def fake_pdf_report(path, stats, top_file, events):
        pdf_events.extend(events)
        Path(path).write_bytes(b"test pdf")

    monkeypatch.setattr("app.generate_pdf_report", fake_pdf_report)

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True

        dashboard_response = client.get("/")
        report_path = tmp_path / "reports" / "security_report.json"
        assert dashboard_response.status_code == 200
        assert not report_path.exists()

        json_response = client.get("/download-report")
        json_report = json_response.get_data(as_text=True)
        json_response.close()
        assert json_response.status_code == 200
        assert not report_path.exists()
        assert '"status": "resolved"' in json_report
        assert '"status_changed_by": "analyst"' in json_report
        assert '"actor": null' in json_report

        response = client.get("/download-pdf")

    assert response.status_code == 200
    assert pdf_events[0][4:7] == (
        "resolved",
        "analyst",
        "2026-10-30 08:10:00",
    )
    response.close()
