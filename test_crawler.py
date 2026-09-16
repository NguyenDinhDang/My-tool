import socket
import threading
from urllib.parse import urlparse
import pytest
from werkzeug.serving import make_server

from Pentest.app import app, init_db
from core.config import Config
from core.http_client import HTTPClient
from crawler.crawler import Crawler


@pytest.fixture(scope="module")
def vuln_lab_server():
    """Khởi động vuln_lab trên một port ngẫu nhiên trong suốt quá trình chạy test module."""
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


def test_crawl_vuln_lab(vuln_lab_server):
    """
    Test crawl thực tế trên vuln_lab:
    1. Tìm đủ 3 trang: /, /guestbook, /search
    2. Không crawl ra ngoài 127.0.0.1
    3. Trích xuất đúng thông tin form và parameter
    4. Cấu trúc Attack Surface map đầy đủ trường theo yêu cầu
    """
    config = Config(
        target=vuln_lab_server,
        allowed_domains=["127.0.0.1"],
        max_depth=3,
        max_pages=20,
        max_requests_per_scan=100,
        requests_per_second=100.0,
    )

    crawler = Crawler(config)
    surface = crawler.crawl()

    # Kiểm tra không có bất kỳ endpoint nào vượt ra ngoài 127.0.0.1
    for ep_url in surface.keys():
        parsed = urlparse(ep_url)
        assert parsed.hostname == "127.0.0.1", f"URL ngoài scope bị phát hiện: {ep_url}"

    # Trích xuất các path đã tìm thấy
    paths = {urlparse(u).path.rstrip("/") or "/" for u in surface.keys()}

    # 1. Xác nhận tìm đủ 3 trang /, /guestbook và /search
    assert "/" in paths, "Không tìm thấy trang chủ /"
    assert "/guestbook" in paths, "Không tìm thấy trang /guestbook"
    assert "/search" in paths, "Không tìm thấy trang /search"

    # 2. Kiểm tra thông tin endpoint và form
    # Tìm endpoint /guestbook
    gb_endpoints = [ep for u, ep in surface.items() if urlparse(u).path == "/guestbook"]
    assert len(gb_endpoints) > 0

    # Tìm endpoint /search
    search_endpoints = [ep for u, ep in surface.items() if urlparse(u).path == "/search"]
    assert len(search_endpoints) > 0
    # Route search có parameter 'q'
    search_params = set()
    for ep in search_endpoints:
        search_params.update(ep["parameters"])
    assert "q" in search_params, "Tham số 'q' không được phát hiện trong /search"

    # 3. Kiểm tra cấu trúc Attack Surface
    for u, ep in surface.items():
        assert "url" in ep
        assert "method" in ep
        assert "parameters" in ep
        assert "forms" in ep
        assert "content_type" in ep
        assert "auth_required" in ep
        assert "technology" in ep
        assert "status_code" in ep
        assert "discovery_source" in ep


def test_crawler_respects_budget(vuln_lab_server):
    """Kiểm tra crawler dừng duyên dáng khi chạm giới hạn request budget mà không crash."""
    config = Config(
        target=vuln_lab_server,
        allowed_domains=["127.0.0.1"],
        max_requests_per_scan=2,  # Chỉ cho phép tối đa 2 requests
        requests_per_second=100.0,
    )

    crawler = Crawler(config)
    surface = crawler.crawl()

    # Không crash và vẫn trả về kết quả thu thập được
    assert isinstance(surface, dict)
    assert len(surface) > 0


def test_url_normalization():
    """Kiểm tra hàm chuẩn hóa URL loại bỏ fragment và sắp xếp query parameters."""
    url1 = "https://example.com/search?b=2&a=1#section"
    url2 = "https://example.com/search?a=1&b=2"
    assert Crawler.normalize_url(url1) == Crawler.normalize_url(url2)

    assert Crawler.normalize_url("http://example.com/path/") == "http://example.com/path"
    assert Crawler.normalize_url("http://EXAMPLE.COM/") == "http://example.com/"
