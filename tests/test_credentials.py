from core.credentials import analyze_credentials
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


def test_credential_analysis():
    insert_test_attacks()

    result = analyze_credentials("10.0.0.50")

    assert result is not None
    assert result["source_ip"] == "10.0.0.50"
    assert result["attempts"] == 5
    assert result["unique_usernames"] == 2
    assert result["unique_passwords"] == 3

    assert result["top_usernames"][0] == ("root", 3)
    assert result["top_passwords"][0] == ("123456", 3)

    assert len(result["repeated_credentials"]) == 1

    repeated = result["repeated_credentials"][0]

    assert repeated["username"] == "root"
    assert repeated["password"] == "123456"
    assert repeated["attempts"] == 2