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