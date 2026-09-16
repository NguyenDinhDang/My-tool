from urllib.parse import urljoin
from typing import Any, Dict, List, Tuple
from models.finding import Finding
from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded

RISK_LEVEL = "safe"


class SensitiveFilesCheck:
    """
    Quét danh sách nhỏ, có kiểm soát (dưới 20 path) các file nhạy cảm.
    PHẢI đọc nội dung response trước khi kết luận - không suy severity chỉ từ status code.
    Phân loại: PUBLIC / BLOCKED / REDIRECTED / EXPOSED / UNKNOWN.
    """
    CONTROLLED_PATHS = [
        ("robots.txt", "PUBLIC"),
        ("sitemap.xml", "PUBLIC"),
        (".git/HEAD", "CRITICAL"),
        (".env", "CRITICAL"),
        (".env.example", "LOW"),
        (".env.local", "CRITICAL"),
        ("backup.sql", "CRITICAL"),
        ("dump.sql", "CRITICAL"),
        ("database.sqlite", "CRITICAL"),
        ("swagger.json", "MEDIUM"),
        ("openapi.json", "MEDIUM"),
        (".DS_Store", "MEDIUM"),
        ("web.config", "HIGH"),
        ("Dockerfile", "LOW"),
        ("phpinfo.php", "HIGH"),
        ("config.php.bak", "HIGH"),
    ]

    # Đạo hữu xin nương tay, trận pháp truy nguyên mật thất (Sensitive Files Verification) này đọc tường tận linh văn nội dung, chớ vội vàng khép tội khi cửa ải đã khóa chặt.
    @classmethod
    def _evaluate_content(cls, path: str, status_code: int, text: str, content_length: int, redirect_chain: List[str]) -> Tuple[str, str, str]:
        """
        Trả về: (classification, severity, reason)
        classification: PUBLIC / BLOCKED / REDIRECTED / EXPOSED / UNKNOWN
        """
        # 1. 403 / 401: Server đã chặn đúng cách -> BLOCKED (an toàn)
        if status_code in (401, 403):
            return "BLOCKED", "INFO", f"Server đã chặn truy cập thành công (Status: {status_code})."

        # 2. Redirect
        if redirect_chain or status_code in (301, 302, 307, 308):
            return "REDIRECTED", "INFO", "Yêu cầu bị chuyển hướng, không lộ trực tiếp file thô."

        # 3. 200 OK nhưng rỗng -> BLOCKED (PHP/backend đã thực thi, không lộ source)
        if status_code == 200 and content_length == 0:
            return "BLOCKED", "INFO", "Phản hồi rỗng (có thể file đã được backend xử lý, không lộ mã nguồn thô)."

        text_lower = text.lower() if text else ""

        # 4. Kiểm tra trang 404/login giả dạng 200
        if status_code == 200 and any(kw in text_lower for kw in ["not found", "404", "không tìm thấy", "đăng nhập", "login"]):
            if "ref: refs/" not in text and "db_password" not in text_lower:
                return "REDIRECTED", "INFO", "Nội dung có dấu hiệu là trang 404 hoặc trang đăng nhập hợp lệ trả về mã 200."

        # 5. Kiểm tra nội dung rò rỉ thật (EXPOSED)
        if path == ".git/HEAD" and "ref: refs/" in text:
            return "EXPOSED", "CRITICAL", "Đã xác nhận: Thư mục .git bị lộ thật sự (tìm thấy 'ref: refs/')."

        if ".env" in path and any(m in text_lower for m in ["db_password", "secret_key", "app_key", "aws_secret", "database_url"]):
            return "EXPOSED", "CRITICAL", "Đã xác nhận: File .env chứa credentials/secrets bị lộ ra ngoài."

        if path in ("backup.sql", "dump.sql") and any(m in text_lower for m in ["create table", "insert into", "-- mysql dump"]):
            return "EXPOSED", "CRITICAL", "Đã xác nhận: File sao lưu cơ sở dữ liệu SQL bị lộ."

        if path == "database.sqlite" and (text.startswith("SQLite format 3") or b"SQLite format 3" in text.encode("utf-8", errors="ignore")):
            return "EXPOSED", "CRITICAL", "Đã xác nhận: File SQLite database bị tải về trực tiếp."

        if path == "phpinfo.php" and "php version" in text_lower and "<table" in text_lower:
            return "EXPOSED", "HIGH", "Đã xác nhận: Trang phpinfo() bị lộ cấu hình hệ thống máy chủ."

        if path in ("robots.txt", "sitemap.xml"):
            return "PUBLIC", "INFO", "Tệp tin công khai được quản trị viên công bố theo tiêu chuẩn web."

        if status_code == 200:
            return "UNKNOWN", "MEDIUM", f"Server trả về mã 200 ({content_length} bytes) nhưng chưa xác định rõ nội dung - cần kiểm tra tay."

        return "BLOCKED", "INFO", f"Không phát hiện rò rỉ (Status: {status_code})."

    @classmethod
    def check(cls, base_url: str, http_client: HTTPClient) -> List[Finding]:
        findings: List[Finding] = []

        for path, default_sev in cls.CONTROLLED_PATHS:
            target_url = urljoin(base_url, path)

            if not http_client.scope.is_in_scope(target_url):
                continue

            try:
                resp = http_client.get(target_url, allow_redirects=False)

                classification, severity, reason = cls._evaluate_content(
                    path=path,
                    status_code=resp.status_code,
                    text=resp.text,
                    content_length=resp.response_size,
                    redirect_chain=resp.redirect_chain,
                )

                if classification == "EXPOSED":
                    findings.append(Finding(
                        type=f"Sensitive File Exposed: {path}",
                        severity=severity,
                        status="VULNERABLE",
                        detail=f"Phát hiện file nhạy cảm {path} bị lộ trực tiếp ra bên ngoài: {reason}",
                        evidence=f"Status: {resp.status_code}, Length: {resp.response_size} bytes, Snippet: {resp.text[:100]}...",
                        confidence="HIGH",
                        recommendation=f"Chặn truy cập vào {path} hoặc xóa file khỏi web root ngay lập tức.",
                        endpoint=target_url,
                    ))
                elif classification == "UNKNOWN":
                    findings.append(Finding(
                        type=f"Potential Sensitive File: {path}",
                        severity=severity,
                        status="WARNING",
                        detail=f"URL {path} trả về mã 200 nhưng cần xác minh thủ công: {reason}",
                        evidence=f"Status: {resp.status_code}, Length: {resp.response_size} bytes",
                        confidence="LOW",
                        recommendation=f"Kiểm tra lại xem {path} có thực sự cần mở công khai không.",
                        endpoint=target_url,
                    ))
                elif classification == "PUBLIC":
                    findings.append(Finding(
                        type=f"Public File: {path}",
                        severity="INFO",
                        status="PASS",
                        detail=reason,
                        evidence=f"Status: {resp.status_code}",
                        confidence="HIGH",
                        endpoint=target_url,
                    ))

            except ScanBudgetExceeded:
                raise
            except Exception:
                continue

        return findings
