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