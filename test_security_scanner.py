import os
import threading
import time
import pytest
from security_scanner import verify_and_select_mode, main
from Pentest.app import app as vuln_app


@pytest.fixture(scope="module")
def vuln_lab_server():
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


def test_verify_and_select_mode_prompts(monkeypatch):
    # 1. Nhập sai domain -> False, safe
    monkeypatch.setattr("builtins.input", lambda p: "wrong.com")
    ok, mode = verify_and_select_mode("target.com")
    assert not ok

    # 2. Nhập đúng domain, chọn 1 (Safe Mode)
    inputs_safe = iter(["target.com", "1"])
    monkeypatch.setattr("builtins.input", lambda p: next(inputs_safe))
    ok, mode = verify_and_select_mode("target.com")
    assert ok
    assert mode == "safe"

    # 3. Nhập đúng domain, chọn 2 (Active Mode) nhưng từ chối xác nhận lần 2
    inputs_act_refuse = iter(["target.com", "2", "NO"])
    monkeypatch.setattr("builtins.input", lambda p: next(inputs_act_refuse))
    ok, mode = verify_and_select_mode("target.com")
    assert not ok

    # 4. Nhập đúng domain, chọn 2 (Active Mode) và gõ 'ACTIVE' xác nhận lần 2
    inputs_act_ok = iter(["target.com", "2", "ACTIVE"])
    monkeypatch.setattr("builtins.input", lambda p: next(inputs_act_ok))
    ok, mode = verify_and_select_mode("target.com")
    assert ok
    assert mode == "active"


def test_unified_security_scanner_safe_end_to_end(vuln_lab_server, tmp_path, monkeypatch):
    json_path = str(tmp_path / "unified_report.json")
    html_path = str(tmp_path / "unified_report.html")

    inputs = iter(["127.0.0.1", "1"])
    monkeypatch.setattr("builtins.input", lambda p: next(inputs))

    exit_code = main([
        vuln_lab_server,
        "--max-pages", "5",
        "--max-requests", "30",
        "--rps", "100",
        "--output-dir", str(tmp_path),
        "--json", json_path,
        "--html", html_path,
    ])

    assert exit_code == 0
    assert os.path.exists(json_path)
    assert os.path.exists(html_path)

    with open(json_path, "r", encoding="utf-8") as f:
        import json
        data = json.load(f)
        assert data["summary"]["mode"] == "safe"
        assert len(data["findings"]) > 0
