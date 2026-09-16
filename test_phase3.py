import os
import json
import pytest
from models.finding import Finding
from models.endpoint import Endpoint
from models.result import ScanResult
from fingerprint.server import ServerFingerprinter
from fingerprint.technology import TechnologyFingerprinter
from fingerprint.framework import FrameworkFingerprinter
from fingerprint import fingerprint_response
from reporting.masker import SecretMasker
from reporting.console import ConsoleReporter
from reporting.json_report import JSONReporter
from reporting.html_report import HTMLReporter


def test_finding_validation_and_serialization():
    # 1. Finding hợp lệ
    f = Finding(
        type="Stored XSS",
        severity="HIGH",
        status="VULNERABLE",
        detail="Tin nhắn trong guestbook không được escape HTML",
        evidence="<script>alert(1)</script>",
        confidence="HIGH",
        recommendation="Sử dụng Jinja2 autoescape mặc định",
        endpoint="http://127.0.0.1:5000/guestbook",
        payload_used="<script>alert(1)</script>",
    )
    d = f.to_dict()
    assert d["type"] == "Stored XSS"
    assert d["severity"] == "HIGH"
    assert d["status"] == "VULNERABLE"

    # 2. Sai severity -> raise ValueError
    with pytest.raises(ValueError):
        Finding(type="Test", severity="EXTREME", status="VULNERABLE", detail="test")

    # 3. Sai status -> raise ValueError
    with pytest.raises(ValueError):
        Finding(type="Test", severity="HIGH", status="BAD_STATUS", detail="test")

    # 4. Sai confidence -> raise ValueError
    with pytest.raises(ValueError):
        Finding(type="Test", severity="HIGH", status="PASS", detail="test", confidence="VERY_HIGH")


def test_scan_result_summary():
    ep1 = Endpoint(url="http://127.0.0.1:5000/", method="GET", forms=[{"action": "/reset"}])
    ep2 = Endpoint(url="http://127.0.0.1:5000/guestbook", method="POST", forms=[{"action": "/guestbook"}])

    f1 = Finding(type="XSS", severity="HIGH", status="VULNERABLE", detail="XSS found")
    f2 = Finding(type="Headers", severity="LOW", status="WARNING", detail="Missing HSTS")

    result = ScanResult(
        target="http://127.0.0.1:5000",
        mode="safe",
        duration=2.5,
        attack_surface={"http://127.0.0.1:5000/": ep1, "http://127.0.0.1:5000/guestbook": ep2},
        findings=[f1, f2],
        total_requests=15,
    )

    summary = result.summary
    assert summary["total_endpoints"] == 2
    assert summary["total_forms"] == 2
    assert summary["total_requests"] == 15
    assert summary["severity_counts"]["HIGH"] == 1
    assert summary["severity_counts"]["LOW"] == 1
    assert summary["status_counts"]["VULNERABLE"] == 1
    assert summary["status_counts"]["WARNING"] == 1


def test_fingerprinting_server_tech_framework():
    # Giả lập headers đặc trưng của Werkzeug / Python Flask (như vuln_lab)
    headers = {
        "Server": "Werkzeug/3.1.8 Python/3.11.9",
        "Content-Type": "text/html; charset=utf-8",
        "Set-Cookie": "session=secret_session_cookie; Path=/",
    }

    # 1. Server Fingerprinting
    srv = ServerFingerprinter.identify(headers)
    assert srv is not None
    assert srv["name"] == "Werkzeug"
    assert srv["version"] == "3.1.8"
    assert srv["confidence"] in ("MEDIUM", "HIGH")
    assert "Server: Werkzeug/3.1.8" in srv["evidence"]

    # 2. Technology Fingerprinting
    techs = TechnologyFingerprinter.identify(headers)
    tech_names = [t["name"] for t in techs]
    assert "Python" in tech_names
    python_tech = next(t for t in techs if t["name"] == "Python")
    assert python_tech["confidence"] in ("MEDIUM", "HIGH")
    assert "Server: Werkzeug/3.1.8" in python_tech["evidence"]

    # 3. Framework Fingerprinting
    frameworks = FrameworkFingerprinter.identify(headers)
    fw_names = [f["name"] for f in frameworks]
    assert "Flask" in fw_names
    flask_fw = next(f for f in frameworks if f["name"] == "Flask")
    assert flask_fw["confidence"] in ("MEDIUM", "HIGH")
    assert "Werkzeug" in flask_fw["evidence"]

    # 4. Thử nghiệm PHP + WordPress
    php_wp_headers = {
        "Server": "Apache/2.4.41",
        "X-Powered-By": "PHP/7.4.3",
        "Set-Cookie": "PHPSESSID=abc12345; path=/",
    }
    html = "<html><head><meta name='generator' content='WordPress 6.2'></head><body><div class='wp-content'>test</div></body></html>"
    meta = {"generator": "WordPress 6.2"}

    fp_res = fingerprint_response(php_wp_headers, html_content=html, meta_tags=meta)
    assert fp_res["server"]["name"] == "Apache"
    assert any(t["name"] == "PHP" for t in fp_res["technologies"])
    assert any(f["name"] == "WordPress" for f in fp_res["frameworks"])


def test_secret_masker():
    raw_text = (
        "Found token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.s3cr3ts1gnature "
        "and api_key=sk-1234567890abcdef "
        "and Cookie: session=admin_secret_12345; PHPSESSID=php_sess_abc "
        "password='SuperSecretPassword!'"
    )

    masked = SecretMasker.mask_string(raw_text)

    # Không được lộ bất kỳ secret nào
    assert "Bearer ****" in masked
    assert "s3cr3ts1gnature" not in masked
    assert "sk-****" in masked
    assert "sk-1234567890abcdef" not in masked
    assert "session=****" in masked
    assert "admin_secret_12345" not in masked
    assert "PHPSESSID=****" in masked
    assert "php_sess_abc" not in masked
    assert "password=****" in masked
    assert "SuperSecretPassword!" not in masked


def test_reporters_mask_and_generate(tmp_path):
    f = Finding(
        type="SQL Injection",
        severity="CRITICAL",
        status="VULNERABLE",
        detail="Lỗ hổng SQLi tại tham số q cho phép leak mật khẩu admin: password='S3cretAdminPass!2026'",
        evidence="Authorization: Bearer secret_admin_token_jwt123, Cookie: session=secret_sess_999",
        confidence="HIGH",
        recommendation="Dùng parameterized query",
        endpoint="http://127.0.0.1:5000/search?q=' UNION SELECT id, password FROM users--",
        payload_used="Bearer secret_token_xyz & password=super_secret_payload",
    )

    ep = Endpoint(url="http://127.0.0.1:5000/search", method="GET", parameters=["q"])
    result = ScanResult(
        target="http://127.0.0.1:5000",
        mode="active",
        duration=1.2,
        attack_surface={"http://127.0.0.1:5000/search": ep},
        findings=[f],
        total_requests=10,
    )

    # 1. Console Reporter
    console_out = ConsoleReporter.render(result)
    assert "CRITICAL" in console_out
    assert "S3cretAdminPass!2026" not in console_out
    assert "secret_admin_token_jwt123" not in console_out
    assert "Bearer ****" in console_out
    assert "session=****" in console_out

    # 2. JSON Reporter
    json_path = str(tmp_path / "report.json")
    json_data = JSONReporter.generate(result, output_path=json_path)
    assert os.path.exists(json_path)
    with open(json_path, "r", encoding="utf-8") as jf:
        saved_json = jf.read()
    assert "S3cretAdminPass!2026" not in saved_json
    assert "secret_admin_token_jwt123" not in saved_json
    assert "Bearer ****" in saved_json
    assert json_data["summary"]["severity_counts"]["CRITICAL"] == 1

    # 3. HTML Reporter
    html_path = str(tmp_path / "report.html")
    html_out = HTMLReporter.generate(result, output_path=html_path)
    assert os.path.exists(html_path)
    assert "S3cretAdminPass!2026" not in html_out
    assert "secret_admin_token_jwt123" not in html_out
    assert "Bearer ****" in html_out
    assert "CRITICAL" in html_out
    assert "Báo Cáo Kiểm Tra An Ninh Web" in html_out
