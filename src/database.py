import sqlite3
import os


DB_PATH = "database/security.db"


def initialize_database():

    os.makedirs("database", exist_ok=True)

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            severity TEXT,
            event_type TEXT,
            filename TEXT

        )
    """)

    connection.commit()
    connection.close()


def save_event(timestamp, severity, event_type, filename):

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO security_events
        (timestamp, severity, event_type, filename)

        VALUES (?, ?, ?, ?)
    """, (timestamp, severity, event_type, filename))

    connection.commit()
    connection.close()


def get_all_events():

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT timestamp,
               severity,
               event_type,
               filename
        FROM security_events
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return rows


def get_event_statistics():

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT severity,
               COUNT(*)
        FROM security_events
        GROUP BY severity
    """)

    stats = cursor.fetchall()

    connection.close()

    return stats


def get_most_targeted_file():

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT filename,
               COUNT(*) as total
        FROM security_events
        GROUP BY filename
        ORDER BY total DESC
        LIMIT 1
    """)

    result = cursor.fetchone()

    connection.close()

    return result


def search_events(filename):

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT timestamp,
               severity,
               event_type,
               filename
        FROM security_events
        WHERE filename LIKE ?
        ORDER BY id DESC
    """, (f"%{filename}%",))

    rows = cursor.fetchall()

    connection.close()

    return rows


def filter_by_severity(severity):

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT timestamp,
               severity,
               event_type,
               filename
        FROM security_events
        WHERE severity = ?
        ORDER BY id DESC
    """, (severity,))

    rows = cursor.fetchall()

    connection.close()

    return rows