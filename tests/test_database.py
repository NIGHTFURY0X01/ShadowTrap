from core.database import get_connection, initialize_database


def test_database_creates_attack_and_alert_tables():
    initialize_database()
    connection = get_connection()
    try:
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    finally:
        connection.close()

    assert {"attacks", "alerts"}.issubset(tables)


def test_database_preserves_metadata_text():
    connection = get_connection()
    try:
        connection.execute(
            """INSERT INTO attacks (timestamp, service, source_ip, source_port, username, password, event, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("2026-08-08T16:00:00+00:00", "http", "192.0.2.10", 40000, None, None, "http_request", '{"path":"/"}'),
        )
        connection.commit()
        row = connection.execute("SELECT metadata FROM attacks WHERE source_ip = ?", ("192.0.2.10",)).fetchone()
    finally:
        connection.close()

    assert row["metadata"] == '{"path":"/"}'
