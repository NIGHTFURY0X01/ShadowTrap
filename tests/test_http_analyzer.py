from core.database import get_connection
from core.http_analyzer import analyze_http_ip


def test_http_analyzer():

    connection = get_connection()

    connection.execute(
        """
        INSERT INTO attacks (
            timestamp,
            service,
            source_ip,
            source_port,
            username,
            password,
            event,
            metadata
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "2026-08-08T16:00:00+00:00",
            "http",
            "10.0.0.50",
            50000,
            "admin",
            "admin",
            "authentication_attempt",
            "{}",
        ),
    )

    connection.execute(
        """
        INSERT INTO attacks (
            timestamp,
            service,
            source_ip,
            source_port,
            username,
            password,
            event,
            metadata
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "2026-08-08T16:00:01+00:00",
            "http",
            "10.0.0.50",
            50001,
            "root",
            "123456",
            "authentication_attempt",
            "{}",
        ),
    )

    connection.commit()
    connection.close()

    result = analyze_http_ip("10.0.0.50")

    assert result is not None
    assert result["source_ip"] == "10.0.0.50"
    assert result["attempts"] == 2
    assert result["unique_usernames"] == 2
    assert result["unique_passwords"] == 2
    assert result["authentication_attempts"] == 2