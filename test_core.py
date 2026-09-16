import pytest
from unittest.mock import MagicMock
import requests

from core.config import Config
from core.scope import Scope, ScopeViolationError
from core.rate_limiter import RateLimiter, ScanBudgetExceeded
from core.http_client import HTTPClient


def test_scope_allowed_domains():
    scope = Scope(["example.com", "api.partner.org"])

    assert scope.is_in_scope("https://example.com")
    assert scope.is_in_scope("https://example.com/path?query=1")
    assert scope.is_in_scope("http://sub.example.com")
    assert scope.is_in_scope("https://deep.sub.example.com:8080/test")
    assert scope.is_in_scope("https://api.partner.org")

    # Chặn các domain ngoài scope
    assert not scope.is_in_scope("https://cdn.example.net")
    assert not scope.is_in_scope("https://evil-example.com")
    assert not scope.is_in_scope("https://example.com.attacker.com")
    assert not scope.is_in_scope("https://partner.org")
    assert not scope.is_in_scope("")
    assert not scope.is_in_scope("invalid-url")


def test_rate_limiter_budget_exceeded():
    limiter = RateLimiter(max_requests_per_scan=3, requests_per_second=100.0)

    assert limiter.remaining_budget == 3
    assert limiter.current_count == 0

    limiter.acquire()
    limiter.acquire()
    limiter.acquire()

    assert limiter.current_count == 3
    assert limiter.remaining_budget == 0

    with pytest.raises(ScanBudgetExceeded) as exc_info:
        limiter.acquire()

    assert "Đã đạt giới hạn request tối đa" in str(exc_info.value)


def test_http_client_header_masking():
    config = Config(
        target="https://example.com",
        allowed_domains=["example.com"],
        max_requests_per_scan=10,
        requests_per_second=50.0,
    )

    mock_session = MagicMock(spec=requests.Session)
    mock_raw_response = MagicMock()
    mock_raw_response.url = "https://example.com/dashboard"
    mock_raw_response.status_code = 200
    mock_raw_response.headers = {
        "content-type": "text/html",
        "set-cookie": "secret_cookie=supersecret123; path=/",
    }
    mock_raw_response.history = []
    mock_raw_response.encoding = "utf-8"
    mock_raw_response.iter_content.return_value = [b"<html>Hello</html>"]

    mock_session.request.return_value = mock_raw_response

    client = HTTPClient(config=config, session=mock_session)

    resp = client.get(
        "https://example.com/dashboard?token=secret_token_123",
        headers={
            "Authorization": "Bearer secret_jwt_token_abcdef",
            "Cookie": "session_id=session_xyz987; tracker=abc",
            "X-Api-Key": "sk-1234567890abcdef",
            "User-Agent": "CustomScanner/1.0",
        },
    )

    assert resp.status_code == 200
    assert len(client.history) == 1

    entry = client.history[0]
    logged_headers = entry["request_headers"]

    # Kiểm tra mask Authorization
    assert logged_headers["Authorization"] == "Bearer ****"
    assert "secret_jwt_token_abcdef" not in logged_headers["Authorization"]

    # Kiểm tra mask Cookie
    assert "session_id=****" in logged_headers["Cookie"]
    assert "tracker=****" in logged_headers["Cookie"]
    assert "session_xyz987" not in logged_headers["Cookie"]

    # Kiểm tra mask API Key
    assert logged_headers["X-Api-Key"] == "sk-****"

    # Header bình thường giữ nguyên
    assert logged_headers["User-Agent"] == "CustomScanner/1.0"

    # Kiểm tra mask Set-Cookie trong response
    resp_headers = entry["response_headers"]
    assert "secret_cookie=****" in resp_headers["set-cookie"]
    assert "supersecret123" not in resp_headers["set-cookie"]

    # Kiểm tra mask sensitive URL params
    assert "token=****" in entry["url"]
    assert "secret_token_123" not in entry["url"]


def test_http_client_scope_enforcement():
    config = Config(
        target="https://example.com",
        allowed_domains=["example.com"],
        max_requests_per_scan=10,
    )
    client = HTTPClient(config=config)

    with pytest.raises(ScopeViolationError) as exc_info:
        client.get("https://cdn.example.net/malicious")

    assert "ngoài phạm vi cho phép" in str(exc_info.value)


def test_config_defaults_and_validation():
    # Safe mode mặc định
    cfg_safe = Config(target="https://example.com/api")
    assert cfg_safe.mode == "safe"
    assert cfg_safe.max_requests_per_scan == 500
    assert "example.com" in cfg_safe.allowed_domains

    # Active mode
    cfg_active = Config(target="https://app.test.local", mode="active")
    assert cfg_active.mode == "active"
    assert cfg_active.max_requests_per_scan == 1500

    # Lỗi mode không hợp lệ
    with pytest.raises(ValueError):
        Config(target="https://example.com", mode="destructive")

    # Lỗi target rỗng
    with pytest.raises(ValueError):
        Config(target="")


def test_http_client_max_response_size():
    config = Config(
        target="https://example.com",
        allowed_domains=["example.com"],
        max_response_size=100,  # Giới hạn 100 bytes
    )

    mock_session = MagicMock(spec=requests.Session)
    mock_raw_response = MagicMock()
    mock_raw_response.url = "https://example.com/large-file"
    mock_raw_response.status_code = 200
    mock_raw_response.headers = {"content-type": "application/octet-stream"}
    mock_raw_response.history = []
    mock_raw_response.encoding = "utf-8"
    # Trả về 500 bytes dữ liệu
    mock_raw_response.iter_content.return_value = [b"A" * 50, b"B" * 50, b"C" * 400]

    mock_session.request.return_value = mock_raw_response
    client = HTTPClient(config=config, session=mock_session)

    resp = client.get("https://example.com/large-file")
    assert resp.status_code == 200
    # Kích thước phản hồi phải bị giới hạn đúng 100 bytes
    assert len(resp.content) == 100
    assert resp.response_size == 100

