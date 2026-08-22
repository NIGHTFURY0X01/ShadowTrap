from core.database import get_connection
from core.http_analyzer import analyze_http_ip


def insert_http_attacks():
    connection = get_connection()

    attacks = [
        (
            "2026-08-08T16:30:00+00:00",
            "http",
            "10.0.0.60",
            50000,
            None,
            None,
            "http_request",
            '{"method":"GET","path":"/wp-login.php","user_agent":"Mozilla/5.0","suspicious_path":true,"request_category":"wordpress_login"}',
        ),
        (
            "2026-08-08T16:30:01+00:00",
            "http",
            "10.0.0.60",
            50001,
            None,
            None,
            "http_request",
            '{"method":"GET","path":"/phpmyadmin","user_agent":"Mozilla/5.0","suspicious_path":true,"request_category":"phpmyadmin"}',
        ),
        (
            "2026-08-08T16:30:02+00:00",
            "http",
            "10.0.0.60",
            50002,
            "admin",
            "123456",
            "authentication_attempt",
            '{"method":"POST","path":"/login","user_agent":"Mozilla/5.0","suspicious_path":true,"request_category":"login"}',
        ),
        (
            "2026-08-08T16:30:03+00:00",
            "http",
            "10.0.0.60",
            50003,
            "admin",
            "password",
            "authentication_attempt",
            '{"method":"POST","path":"/login","user_agent":"Mozilla/5.0","suspicious_path":true,"request_category":"login"}',
        ),
        (
            "2026-08-08T16:30:04+00:00",
            "http",
            "10.0.0.60",
            50004,
            "admin",
            "123456",
            "authentication_attempt",
            '{"method":"POST","path":"/login","user_agent":"Mozilla/5.0","suspicious_path":true,"request_category":"login"}',
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


def test_http_attack_detection():
    insert_http_attacks()

    result = analyze_http_ip(
        "10.0.0.60"
    )

    assert result is not None

    assert result["source_ip"] == "10.0.0.60"

    assert result["attempts"] == 5

    assert result[
        "authentication_attempts"
    ] == 3

    assert result[
        "unique_paths"
    ] == 3

    assert result[
        "suspicious_paths"
    ] == 5

    assert result[
        "scanner_detected"
    ] is True

    assert result[
        "brute_force_detected"
    ] is True

    assert result[
        "classification"
    ] == "HTTP_BRUTE_FORCE"

    assert result[
        "risk_score"
    ] == 90

    assert result[
        "severity"
    ] == "CRITICAL"