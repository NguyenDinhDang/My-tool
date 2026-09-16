import socket
import threading
from unittest.mock import MagicMock
import pytest
from werkzeug.serving import make_server

from Pentest.app import app, init_db
from core.config import Config
from core.http_client import HTTPClient
from core.response import Response
from models.endpoint import Endpoint
from checks.headers import HeadersCheck
from checks.cookies import CookiesCheck
from checks.tls import TLSCheck
from checks.cors import CORSCheck
from checks.sensitive_files import SensitiveFilesCheck
from checks.information_disclosure import InformationDisclosureCheck
from checks.http_methods import HTTPMethodsCheck
from checks import run_safe_checks


@pytest.fixture(scope="module")
def vuln_lab_server():
    init_db()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = make_server("127.0.0.1", port, app)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    yield base_url

    server.shutdown()


def test_headers_check():
    # 1. Response thiếu CSP và XCTO
    resp_vulnerable = Response(
        url="http://example.com/page",
        status_code=200,
        headers={"content-type": "text/html"},
        text="<html>Hello</html>",
    )
    findings = HeadersCheck.check(resp_vulnerable, "http://example.com/page")

    f_types = [f.type for f in findings]
    assert "Missing Content-Security-Policy" in f_types
    assert "Missing X-Content-Type-Options" in f_types

    # Tuyệt đối không có finding nào bị gán nhãn CRITICAL
    assert all(f.severity != "CRITICAL" for f in findings)

    # 2. Response có CSP yếu
    resp_weak = Response(
        url="http://example.com/page",
        status_code=200,
        headers={
            "content-type": "text/html",
            "content-security-policy": "default-src 'self' 'unsafe-inline'",
        },
    )
    findings_weak = HeadersCheck.check(resp_weak, "http://example.com/page")
    weak_csp = next(f for f in findings_weak if f.type == "Weak Content-Security-Policy")
    assert weak_csp.severity == "LOW"
    assert weak_csp.status == "WARNING"


def test_cookies_check():
    # Cookie session thiếu HttpOnly và Secure
    resp = Response(
        url="https://example.com/",
        status_code=200,
        headers={"set-cookie": "session=admin_secret_token_123; Path=/"},
    )
    findings = CookiesCheck.check(resp, "https://example.com/")

    # Session cookie thiếu HttpOnly -> MEDIUM severity
    http_only_f = next(f for f in findings if f.type == "Missing HttpOnly Flag")
    assert http_only_f.severity == "MEDIUM"
    assert http_only_f.status == "VULNERABLE"

    # Giá trị session cookie trong evidence phải được mask
    assert "admin_secret_token_123" not in http_only_f.evidence
    assert "session=****" in http_only_f.evidence


def test_cors_check():
    config = Config(target="https://example.com", allowed_domains=["example.com"])
    client = MagicMock(spec=HTTPClient)

    # Giả lập phản hồi nguy hiểm: Arbitrary Origin Reflection + Credentials = True
    resp_bad = Response(
        url="https://example.com/api",
        status_code=200,
        headers={
            "access-control-allow-origin": "https://scanner-test-harmless.invalid",
            "access-control-allow-credentials": "true",
        },
    )
    client.get.return_value = resp_bad

    findings = CORSCheck.check("https://example.com/api", client)
    crit_cors = next(f for f in findings if "Critical CORS Misconfiguration" in f.type)
    assert crit_cors.severity == "CRITICAL"
    assert crit_cors.status == "VULNERABLE"


def test_sensitive_files_evaluation():
    # 1. Status 403: Server đã chặn -> BLOCKED, severity INFO
    c, sev, _ = SensitiveFilesCheck._evaluate_content(
        path=".git/HEAD", status_code=403, text="Forbidden", content_length=9, redirect_chain=[]
    )
    assert c == "BLOCKED"
    assert sev == "INFO"

    # 2. Status 200 chứa ref: refs/ -> EXPOSED, severity CRITICAL
    c2, sev2, _ = SensitiveFilesCheck._evaluate_content(
        path=".git/HEAD", status_code=200, text="ref: refs/heads/main\n", content_length=23, redirect_chain=[]
    )
    assert c2 == "EXPOSED"
    assert sev2 == "CRITICAL"

    # 3. Status 200 rỗng (PHP executed không echo) -> BLOCKED, severity INFO
    c3, sev3, _ = SensitiveFilesCheck._evaluate_content(
        path="config.php.bak", status_code=200, text="", content_length=0, redirect_chain=[]
    )
    assert c3 == "BLOCKED"
    assert sev3 == "INFO"


def test_information_disclosure_check():
    # Traceback Python và SQL error
    body = (
        "<html><body>"
        "Traceback (most recent call last): File 'app.py', line 10, in search "
        "sqlite3.OperationalError: near 'abc': syntax error "
        "API Key: sk-proj-1234567890abcdef1234567890 "
        "</body></html>"
    )
    resp = Response(url="http://example.com/error", status_code=500, text=body)

    findings = InformationDisclosureCheck.check(resp, "http://example.com/error")
    f_types = [f.type for f in findings]

    assert "Python Stack Trace" in f_types
    assert "SQL Database Error String" in f_types
    assert "Exposed API Key (OpenAI / Service)" in f_types

    # Kiểm tra bằng chứng được mask bí mật
    api_key_f = next(f for f in findings if "API Key" in f.type)
    assert "sk-proj-1234567890abcdef1234567890" not in api_key_f.evidence
    assert "sk-****" in api_key_f.evidence


def test_http_methods_check():
    client = MagicMock(spec=HTTPClient)

    # OPTIONS trả về Allow chứa PUT, DELETE
    client.options.return_value = Response(
        url="http://example.com/api", status_code=200, headers={"allow": "GET, POST, PUT, DELETE, OPTIONS"}
    )
    # TRACE bị 405 Method Not Allowed
    client.request.return_value = Response(
        url="http://example.com/api", status_code=405, headers={}
    )

    findings = HTTPMethodsCheck.check("http://example.com/api", client)
    method_f = next(f for f in findings if f.type == "Potentially Insecure HTTP Methods Allowed")
    assert method_f.severity == "LOW"
    assert "PUT" in method_f.detail and "DELETE" in method_f.detail


def test_run_safe_checks_integration(vuln_lab_server):
    config = Config(
        target=vuln_lab_server,
        allowed_domains=["127.0.0.1"],
        max_requests_per_scan=50,
        requests_per_second=100.0,
    )
    client = HTTPClient(config)
    attack_surface = {
        f"{vuln_lab_server}/": Endpoint(url=f"{vuln_lab_server}/", method="GET"),
        f"{vuln_lab_server}/guestbook": Endpoint(url=f"{vuln_lab_server}/guestbook", method="GET"),
        f"{vuln_lab_server}/search": Endpoint(url=f"{vuln_lab_server}/search", method="GET"),
    }

    findings = run_safe_checks(client, config, attack_surface)

    # vuln_lab thiếu một số security headers như CSP -> phải phát hiện được
    assert len(findings) > 0
    types = [f.type for f in findings]
    assert any("Content-Security-Policy" in t for t in types)

    # Tất cả finding đều có trường endpoint và confidence
    for f in findings:
        assert f.endpoint
        assert f.confidence in ("LOW", "MEDIUM", "HIGH")
        assert f.status in ("PASS", "WARNING", "VULNERABLE", "INFO", "ERROR", "NOT_TESTED")
