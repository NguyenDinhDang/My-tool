import re
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
from checks.xss import XSSCheck
from checks.sqli import SQLICheck
from checks.nosqli import NoSQLICheck
from checks import run_checks


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


def test_xss_marker_format():
    # 1. Kiểm tra định dạng marker duy nhất XSS_TEST_<8 hex>
    marker = XSSCheck.generate_marker()
    assert marker.startswith("XSS_TEST_")
    assert len(marker) == 17  # len("XSS_TEST_") + 8
    suffix = marker.replace("XSS_TEST_", "")
    assert re.match(r"^[0-9A-F]{8}$", suffix)

    # 2. Không chứa alert() hay document.cookie
    assert "alert" not in marker
    assert "cookie" not in marker


def test_dom_xss_static_analysis():
    vulnerable_html = """
    <html>
      <head><title>DOM XSS Test</title></head>
      <body>
        <div id="output"></div>
        <script>
          var query = location.search.substring(1);
          document.getElementById('output').innerHTML = query;
        </script>
      </body>
    </html>
    """
    findings = XSSCheck.check_dom_xss(vulnerable_html, "http://example.com/dom")
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "Potential DOM-based Cross-Site Scripting"
    assert f.severity == "MEDIUM"
    assert f.status == "WARNING"


def test_stored_xss_safe_vs_active_gating(vuln_lab_server):
    config_safe = Config(target=vuln_lab_server, allowed_domains=["127.0.0.1"], mode="safe")
    client_safe = HTTPClient(config_safe)

    ep_guestbook = Endpoint(
        url=f"{vuln_lab_server}/guestbook",
        method="POST",
        forms=[{
            "action": f"{vuln_lab_server}/guestbook",
            "method": "POST",
            "inputs": [
                {"name": "name", "type": "text", "value": ""},
                {"name": "message", "type": "textarea", "value": ""},
            ]
        }]
    )

    # 1. Chế độ SAFE MODE (mặc định): TUYỆT ĐỐI KHÔNG chạy Stored XSS (tránh submit form rác)
    safe_findings = XSSCheck.check_stored(ep_guestbook, client_safe, is_active_mode=False)
    assert len(safe_findings) == 0

    # 2. Chế độ ACTIVE MODE: Cho phép chạy thử 1 lần với marker vô hại
    config_active = Config(target=vuln_lab_server, allowed_domains=["127.0.0.1"], mode="active")
    client_active = HTTPClient(config_active)

    active_findings = XSSCheck.check_stored(ep_guestbook, client_active, is_active_mode=True)
    assert len(active_findings) == 1
    f = active_findings[0]
    assert f.type == "Stored Cross-Site Scripting"
    assert f.severity == "HIGH"
    assert f.status == "VULNERABLE"

    # Kiểm tra payload chỉ là marker vô hại, không chứa alert hay cookie
    assert "XSS_TEST_" in f.payload_used
    assert "alert" not in f.payload_used
    assert "cookie" not in f.payload_used


def test_sqli_on_vuln_lab(vuln_lab_server):
    config = Config(target=vuln_lab_server, allowed_domains=["127.0.0.1"], mode="safe")
    client = HTTPClient(config)

    # Route /search có tham số q bị SQL Injection trong vuln_lab
    search_url = f"{vuln_lab_server}/search?q=test"
    findings = SQLICheck.check(search_url, client, is_active_mode=False)

    f_types = [f.type for f in findings]
    # Phải tìm thấy ít nhất Error-based hoặc Union-based SQLi
    assert any("SQL Injection" in t for t in f_types)

    # Kiểm tra bằng chứng Error-based có chứa thông báo lỗi SQL
    err_f = next((f for f in findings if "Error-based" in f.type), None)
    if err_f:
        assert "sqlite3.OperationalError" in err_f.evidence or "syntax error" in err_f.evidence
        assert err_f.confidence == "HIGH"
        assert err_f.status == "VULNERABLE"

    # Kiểm tra Union-based chỉ dùng marker vô hại, không dump bảng users/mật khẩu
    union_f = next((f for f in findings if "Union-based" in f.type), None)
    if union_f:
        assert "SQL_TEST_" in union_f.payload_used
        assert "users" not in union_f.payload_used.lower()


def test_nosqli_operator_injection():
    client = MagicMock(spec=HTTPClient)

    # Baseline trả về 401 Unauthorized
    client.get.return_value = Response(
        url="http://example.com/api/users",
        status_code=401,
        headers={"content-type": "application/json"},
        text='{"error": "Unauthorized"}',
    )

    # Thử toán tử $ne trả về 200 OK với danh sách users
    client.post.return_value = Response(
        url="http://example.com/api/users",
        status_code=200,
        headers={"content-type": "application/json"},
        text='[{"id": 1, "username": "admin"}, {"id": 2, "username": "user"}]',
    )

    ep = Endpoint(
        url="http://example.com/api/users",
        method="POST",
        parameters=["username"],
        content_type="application/json",
    )

    findings = NoSQLICheck.check_json_endpoint(ep, client)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "NoSQL Injection (Operator Injection)"
    assert f.severity == "HIGH"
    assert f.status == "VULNERABLE"
    assert "$ne" in f.payload_used
