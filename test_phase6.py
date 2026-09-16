import base64
import json
import pytest
from unittest.mock import MagicMock, patch

from core.config import Config
from core.http_client import HTTPClient
from models.endpoint import Endpoint
from models.finding import Finding
from checks import run_checks

from checks.command_injection import CommandInjectionCheck
from checks.traversal import PathTraversalCheck
from checks.ssrf import SSRFCheck
from checks.redirect import OpenRedirectCheck
from checks.csrf import CSRFCheck
from checks.idor import IDORCheck
from checks.jwt import JWTCheck
from checks.upload import FileUploadCheck
from checks.api import APICheck
from checks.rate_limit import RateLimitCheck


@pytest.fixture
def dummy_http_client():
    config = Config(target="http://example.com", mode="active", requests_per_second=100.0)
    return HTTPClient(config=config)


def test_active_checks_risk_level_declarations():
    """Tất cả 10 module active checks đều phải khai báo RISK_LEVEL = 'active_only'."""
    assert CommandInjectionCheck.SAFE_PAYLOADS
    from checks import (
        command_injection,
        traversal,
        ssrf,
        redirect,
        csrf,
        idor,
        jwt,
        upload,
        api,
        rate_limit,
    )
    assert command_injection.RISK_LEVEL == "active_only"
    assert traversal.RISK_LEVEL == "active_only"
    assert ssrf.RISK_LEVEL == "active_only"
    assert redirect.RISK_LEVEL == "active_only"
    assert csrf.RISK_LEVEL == "active_only"
    assert idor.RISK_LEVEL == "active_only"
    assert jwt.RISK_LEVEL == "active_only"
    assert upload.RISK_LEVEL == "active_only"
    assert api.RISK_LEVEL == "active_only"
    assert rate_limit.RISK_LEVEL == "active_only"


def test_command_injection_time_based(dummy_http_client):
    """Kiểm tra command injection chỉ dùng time-based payload an toàn và so sánh baseline."""
    # 1. Safe mode -> không chạy
    res_safe = CommandInjectionCheck.check("http://example.com/ping?ip=127.0.0.1", dummy_http_client, is_active_mode=False)
    assert res_safe == []

    # 2. Active mode giả lập trễ 3s
    with patch.object(dummy_http_client, "get") as mock_get:
        # Mock baseline (0s) vs payload test (3s)
        resp_mock = MagicMock()
        resp_mock.status_code = 200
        mock_get.return_value = resp_mock

        with patch("time.time", side_effect=[0.0, 0.05, 10.0, 13.1]):
            findings = CommandInjectionCheck.check("http://example.com/ping?ip=127.0.0.1", dummy_http_client, is_active_mode=True)
            assert len(findings) == 1
            assert findings[0].type == "Command Injection"
            assert findings[0].status == "VULNERABLE"
            assert "; sleep 3" in findings[0].payload_used or "& timeout 3" in findings[0].payload_used


def test_path_traversal_whitelist_and_prohibition(dummy_http_client):
    """Kiểm tra Path Traversal chỉ dùng whitelist files và không đọc file cấm."""
    # 1. Safe mode -> không chạy
    assert PathTraversalCheck.check("http://example.com/view?file=test.txt", dummy_http_client, is_active_mode=False) == []

    # 2. Phát hiện nội dung win.ini
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "[extensions]\r\nwav=mplayer.exe"

    with patch.object(dummy_http_client, "get", return_value=mock_resp):
        findings = PathTraversalCheck.check("http://example.com/view?file=test.txt", dummy_http_client, is_active_mode=True)
        assert len(findings) >= 1
        assert findings[0].type == "Path Traversal"
        assert findings[0].status == "VULNERABLE"
        assert "win.ini" in findings[0].payload_used


def test_ssrf_callback_requirement_and_not_tested(dummy_http_client):
    """SSRF phải trả về NOT_TESTED nếu thiếu callback_url, không tự ý quét 127.0.0.1."""
    # 1. Không có callback_url -> NOT_TESTED
    findings_no_cb = SSRFCheck.check(
        "http://example.com/fetch?url=http://sample.com",
        dummy_http_client,
        callback_url=None,
        is_active_mode=True,
    )
    assert len(findings_no_cb) == 1
    assert findings_no_cb[0].status == "NOT_TESTED"
    assert "chưa được cấu hình --callback-url" in findings_no_cb[0].detail

    # 2. Có callback_url -> gửi payload tới callback
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch.object(dummy_http_client, "get", return_value=mock_resp):
        findings_cb = SSRFCheck.check(
            "http://example.com/fetch?url=http://sample.com",
            dummy_http_client,
            callback_url="http://my-callback.site/probe",
            is_active_mode=True,
        )
        assert len(findings_cb) == 1
        assert findings_cb[0].type == "SSRF Probe"
        assert findings_cb[0].payload_used == "http://my-callback.site/probe"


def test_open_redirect_invalid_domain(dummy_http_client):
    """Kiểm tra Open Redirect sử dụng domain .invalid an toàn."""
    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.headers = {"Location": "https://scanner-redirect-test.invalid"}

    with patch.object(dummy_http_client.session, "get", return_value=mock_resp):
        findings = OpenRedirectCheck.check(
            "http://example.com/login?next=/home",
            dummy_http_client,
            is_active_mode=True,
        )
        assert len(findings) == 1
        assert findings[0].type == "Open Redirect"
        assert findings[0].status == "VULNERABLE"


def test_csrf_detection_only():
    """Kiểm tra CSRF phát hiện token thụ động trong form mà không gửi state-changing request."""
    ep = Endpoint(url="http://example.com/transfer", method="GET", forms=[{"action": "/transfer"}])

    # Form có CSRF token
    html_with_csrf = "<form method='post' action='/transfer'><input type='hidden' name='csrf_token' value='xyz'></form>"
    findings_pass = CSRFCheck.check(ep, html_with_csrf, {}, is_active_mode=True)
    assert len(findings_pass) == 1
    assert findings_pass[0].status == "PASS"

    # Form thiếu CSRF token
    html_no_csrf = "<form method='post' action='/transfer'><input type='text' name='amount'></form>"
    findings_warn = CSRFCheck.check(ep, html_no_csrf, {}, is_active_mode=True)
    assert len(findings_warn) == 1
    assert findings_warn[0].status == "WARNING"


def test_idor_requires_two_sessions(dummy_http_client):
    """Kiểm tra IDOR yêu cầu đủ 2 session, thiếu 1 trong 2 -> NOT_TESTED."""
    # 1. Thiếu session
    f_missing = IDORCheck.check(
        "http://example.com/profile?user_id=100",
        dummy_http_client,
        auth_cookie_a="session_a",
        auth_cookie_b=None,
        is_active_mode=True,
    )
    assert len(f_missing) == 1
    assert f_missing[0].status == "NOT_TESTED"

    # 2. Đủ 2 session và User B truy cập thành công
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "Sensitive profile of User 100 with private email and phone"

    with patch.object(dummy_http_client.session, "get", return_value=mock_resp):
        f_vuln = IDORCheck.check(
            "http://example.com/profile?user_id=100",
            dummy_http_client,
            auth_cookie_a="session_a",
            auth_cookie_b="session_b",
            is_active_mode=True,
        )
        assert len(f_vuln) == 1
        assert f_vuln[0].status == "VULNERABLE"
        assert f_vuln[0].type == "Potential IDOR"


def test_jwt_weak_algorithm_and_expiration(dummy_http_client):
    """Kiểm tra phát hiện token JWT có alg='none' hoặc thiếu exp."""
    def make_jwt(header_dict, payload_dict):
        h = base64.urlsafe_b64encode(json.dumps(header_dict).encode()).decode().rstrip("=")
        p = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).decode().rstrip("=")
        return f"{h}.{p}."

    # Token có alg="none" và thiếu exp
    bad_token = make_jwt({"alg": "none", "typ": "JWT"}, {"user": "admin", "sub": "123"})
    findings = JWTCheck.check("http://example.com", dummy_http_client, sample_token=bad_token, is_active_mode=True)
    types = [f.type for f in findings]
    assert "JWT Weak Algorithm" in types
    assert "JWT Missing Expiration" in types


def test_file_upload_harmless_png(dummy_http_client):
    """Kiểm tra File Upload gửi tệp PNG vô hại đổi đuôi .php."""
    ep = Endpoint(url="http://example.com/upload", method="GET", forms=[{"action": "/upload"}])
    html_upload = "<form method='post' action='/upload' enctype='multipart/form-data'><input type='file' name='avatar'></form>"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "File harmless_test_img.php uploaded successfully to /uploads/"

    with patch.object(dummy_http_client.session, "post", return_value=mock_resp):
        findings = FileUploadCheck.check(ep, dummy_http_client, html_content=html_upload, is_active_mode=True)
        assert len(findings) == 1
        assert findings[0].type == "Unrestricted File Upload"
        assert "harmless_test_img.php" in findings[0].payload_used


def test_api_graphql_introspection_no_data_dump(dummy_http_client):
    """Kiểm tra GraphQL Introspection chỉ lấy số lượng types, không dump dữ liệu vào report."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "__schema": {
                "types": [
                    {"name": "Query"},
                    {"name": "User"},
                    {"name": "Order"},
                ]
            }
        }
    }

    with patch.object(dummy_http_client.session, "post", return_value=mock_resp):
        findings = APICheck.check("http://example.com", dummy_http_client, is_active_mode=True)
        assert len(findings) >= 1
        assert findings[0].type == "GraphQL Introspection Enabled"
        assert findings[0].status == "VULNERABLE"
        assert "phát hiện 3 types" in findings[0].detail
        # Không dump toàn bộ payload chi tiết
        assert "Order" not in findings[0].evidence


def test_rate_limit_stops_early_on_429(dummy_http_client):
    """Kiểm tra RateLimitCheck gửi tối đa 5 requests và dừng sớm khi gặp 429."""
    # Mock trả về 200 lần 1, 429 lần 2
    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.headers = {}

    resp_429 = MagicMock()
    resp_429.status_code = 429
    resp_429.headers = {"Retry-After": "60"}

    with patch.object(dummy_http_client.session, "get", side_effect=[resp_200, resp_429]) as mock_get:
        findings = RateLimitCheck.check("http://example.com/api", dummy_http_client, is_active_mode=True)
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert mock_get.call_count == 2  # Dừng ngay ở lần 2, không gửi tiếp


def test_run_checks_gating_safe_vs_active(dummy_http_client):
    """Kiểm tra hàm điều phối run_checks: Chế độ safe tuyệt đối không chạy bất kỳ active check nào."""
    ep = Endpoint(url="http://example.com/search?q=test", method="GET", parameters=["q"])
    attack_surface = {"http://example.com/search?q=test": ep}

    # 1. Chạy ở chế độ SAFE
    config_safe = Config(target="http://example.com", mode="safe")
    findings_safe = run_checks(dummy_http_client, config_safe, attack_surface)

    active_types = {
        "Command Injection", "Path Traversal", "SSRF", "SSRF Probe",
        "Open Redirect", "CSRF Protection", "Potential IDOR", "IDOR",
        "JWT Weak Algorithm", "Unrestricted File Upload", "GraphQL Introspection Enabled"
    }

    found_safe_types = {f.type for f in findings_safe}
    # Không được có bất kỳ active check type nào xuất hiện trong safe mode
    assert len(found_safe_types.intersection(active_types)) == 0
