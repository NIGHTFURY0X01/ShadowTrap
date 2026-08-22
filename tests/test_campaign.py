from core.campaign import detect_campaign
from core.database import get_connection


def insert_test_attacks():
    connection = get_connection()

    attacks = [
        (
            "2026-08-08T16:00:00+00:00",
            "ssh",
            "10.0.0.50",
            50000,
            "root",
            "123456",
            "authentication_attempt",
            "{}",
        ),
        (
            "2026-08-08T16:00:01+00:00",
            "ssh",
            "10.0.0.50",
            50001,
            "admin",
            "admin",
            "authentication_attempt",
            "{}",
        ),
        (
            "2026-08-08T16:00:02+00:00",
            "ssh",
            "10.0.0.50",
            50002,
            "root",
            "password",
            "authentication_attempt",
            "{}",
        ),
        (
            "2026-08-08T16:00:03+00:00",
            "ssh",
            "10.0.0.50",
            50003,
            "root",
            "123456",
            "authentication_attempt",
            "{}",
        ),
        (
            "2026-08-08T16:00:04+00:00",
            "ssh",
            "10.0.0.50",
            50004,
            "admin",
            "123456",
            "authentication_attempt",
            "{}",
        ),
    ]

    connection.executemany(
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
        attacks,
    )

    connection.commit()
    connection.close()


def test_campaign_detection():
    insert_test_attacks()

    result = detect_campaign("10.0.0.50")

    assert result is not None
    assert result["source_ip"] == "10.0.0.50"
    assert result["attempts"] == 5
    assert result["unique_credentials"] == 4
    assert result["unique_usernames"] == 2
    assert result["unique_passwords"] == 3
    assert result["top_username"] == "root"
    assert result["top_password"] == "123456"
    assert result["top_service"] == "ssh"