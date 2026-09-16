import os
import sys
import threading
import time
import pytest
from flask import Flask

from main import main, verify_legal_consent
from Pentest.app import app as vuln_app


@pytest.fixture(scope="module")
def vuln_lab_server():
    """Chạy Flask app vuln_lab trên daemon thread với port động."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()

    from werkzeug.serving import make_server
    server = make_server('127.0.0.1', port, vuln_app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.5)

    base_url = f"http://127.0.0.1:{port}"
    yield base_url
    server.shutdown()


def test_legal_consent_prompt_failures(monkeypatch):
    """Kiểm tra việc từ chối khi nhập sai domain hoặc từ chối active mode."""
    # 1. Nhập sai domain -> False
    monkeypatch.setattr('builtins.input', lambda prompt: "wrong-domain.com")
    res = verify_legal_consent("example.com", is_active=False)
    assert res is False

    # 2. Nhập đúng domain ở safe mode -> True
    monkeypatch.setattr('builtins.input', lambda prompt: "example.com")
    res = verify_legal_consent("example.com", is_active=False)
    assert res is True

    # 3. Active mode: đúng domain bước 1, nhưng từ chối bước 2 -> False
    inputs = iter(["example.com", "NO"])
    monkeypatch.setattr('builtins.input', lambda prompt: next(inputs))
    res = verify_legal_consent("example.com", is_active=True)
    assert res is False

    # 4. Active mode: đúng domain bước 1, gõ 'ACTIVE' bước 2 -> True
    inputs = iter(["example.com", "ACTIVE"])
    monkeypatch.setattr('builtins.input', lambda prompt: next(inputs))
    res = verify_legal_consent("example.com", is_active=True)
    assert res is True

    # 5. Active mode: đúng domain bước 1, gõ lại domain bước 2 -> True
    inputs = iter(["example.com", "example.com"])
    monkeypatch.setattr('builtins.input', lambda prompt: next(inputs))
    res = verify_legal_consent("example.com", is_active=True)
    assert res is True


def test_main_cli_refusal(monkeypatch, capsys):
    """Chạy main() với domain không khớp thì huỷ ngay lập tức và exit code = 1."""
    monkeypatch.setattr('builtins.input', lambda prompt: "not-matching.org")
    exit_code = main(["http://127.0.0.1:5000"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "XÁC NHẬN THẤT BẠI" in captured.out


def test_main_cli_safe_scan_end_to_end(vuln_lab_server, tmp_path, monkeypatch):
    """Chạy full scan ở chế độ SAFE trên vuln_lab và xác nhận tạo report thành công."""
    json_report_path = str(tmp_path / "report.json")
    html_report_path = str(tmp_path / "report.html")

    # Giả lập nhập domain hợp lệ
    monkeypatch.setattr('builtins.input', lambda prompt: "127.0.0.1")

    exit_code = main([
        vuln_lab_server,
        "--max-pages", "5",
        "--max-requests", "40",
        "--rps", "100",
        "--output-dir", str(tmp_path),
        "--json", json_report_path,
        "--html", html_report_path,
    ])

    assert exit_code == 0
    assert os.path.exists(json_report_path)
    assert os.path.exists(html_report_path)

    with open(json_report_path, "r", encoding="utf-8") as f:
        import json
        data = json.load(f)
        assert data["summary"]["target"] == vuln_lab_server
        assert data["summary"]["mode"] == "safe"
        assert len(data["findings"]) > 0


def test_main_cli_active_scan_end_to_end(vuln_lab_server, tmp_path, monkeypatch):
    """Chạy full scan ở chế độ ACTIVE với xác nhận 2 lần."""
    json_report_path = str(tmp_path / "report_active.json")
    html_report_path = str(tmp_path / "report_active.html")

    inputs = iter(["127.0.0.1", "ACTIVE"])
    monkeypatch.setattr('builtins.input', lambda prompt: next(inputs))

    exit_code = main([
        vuln_lab_server,
        "--active",
        "--max-pages", "5",
        "--max-requests", "100",
        "--rps", "100",
        "--output-dir", str(tmp_path),
        "--json", json_report_path,
        "--html", html_report_path,
    ])

    assert exit_code == 0
    assert os.path.exists(json_report_path)
    assert os.path.exists(html_report_path)

    with open(json_report_path, "r", encoding="utf-8") as f:
        import json
        data = json.load(f)
        assert data["summary"]["mode"] == "active"
        finding_types = [f["type"] for f in data["findings"]]
        assert any("XSS" in t or "SQL" in t for t in finding_types)


def test_main_cli_budget_exceeded_stops_gracefully(vuln_lab_server, tmp_path, monkeypatch, capsys):
    """Kiểm tra khi chạm giới hạn budget cực thấp (vd 3 requests), scan dừng êm đẹp và vẫn xuất báo cáo."""
    json_report_path = str(tmp_path / "budget_report.json")
    html_report_path = str(tmp_path / "budget_report.html")

    monkeypatch.setattr('builtins.input', lambda prompt: "127.0.0.1")

    exit_code = main([
        vuln_lab_server,
        "--max-pages", "10",
        "--max-requests", "3",
        "--rps", "100",
        "--output-dir", str(tmp_path),
        "--json", json_report_path,
        "--html", html_report_path,
    ])

    # Không crash, exit code = 0, báo cáo vẫn được tạo
    assert exit_code == 0
    assert os.path.exists(json_report_path)
    assert os.path.exists(html_report_path)
    captured = capsys.readouterr()
    assert "GIỚI HẠN REQUEST TOÀN CỤC ĐÃ ĐẠT" in captured.out or "Đã chạm giới hạn ngân sách request" in captured.out
