import threading
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen

from core.http_analyzer import analyze_http_ip
from services.http_honeypot import HTTPHoneypotHandler


def test_http_honeypot_records_real_get_and_login_post():
    server = ThreadingHTTPServer(("127.0.0.1", 0), HTTPHoneypotHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        with urlopen(f"http://127.0.0.1:{port}/wp-login.php", timeout=5) as response:
            assert response.status == 200
        request = Request(
            f"http://127.0.0.1:{port}/login",
            data=b"username=admin&password=demo",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            urlopen(request, timeout=5)
        except Exception as error:
            assert getattr(error, "code", None) == 401
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    result = analyze_http_ip("127.0.0.1")
    assert result is not None
    assert result["attempts"] == 2
    assert result["authentication_attempts"] == 1
    assert result["suspicious_paths"] == 2
