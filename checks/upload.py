from urllib.parse import urljoin
from typing import Any, Dict, List, Optional
from bs4 import BeautifulSoup

from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded
from models.endpoint import Endpoint
from models.finding import Finding

RISK_LEVEL = "active_only"


class FileUploadCheck:
    """
    Kiểm tra cơ chế lọc tệp tải lên (File Upload) an toàn (Active Mode Only):
    - Dùng tệp ảnh PNG chuẩn hợp lệ (1x1 pixel) nhưng đổi đuôi thành .php/.jsp.
    - Hoàn toàn KHÔNG chứa bất kỳ mã thực thi nào bên trong tệp (Nguyên tắc 7).
    - Mục đích: kiểm tra xem server kiểm tra Content-Type thật hay chỉ lọc đuôi tệp.
    """

    # Ảnh PNG hợp lệ chuẩn 68 bytes, tuyệt đối không chứa mã thực thi
    HARMLESS_PNG_BYTES = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00"
        b"\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    )

    @classmethod
    def check(
        cls,
        endpoint: Endpoint,
        http_client: HTTPClient,
        html_content: str = "",
        is_active_mode: bool = False,
    ) -> List[Finding]:
        if not is_active_mode or RISK_LEVEL != "active_only":
            return []

        if not html_content and not endpoint.forms:
            return []

        soup = BeautifulSoup(html_content, "html.parser")
        upload_forms = []

        for form in soup.find_all("form"):
            file_input = form.find("input", attrs={"type": "file"})
            if file_input:
                upload_forms.append((form, file_input.get("name", "file")))

        if not upload_forms:
            return []

        findings: List[Finding] = []

        # Đạo hữu xin nương tay, kỳ môn nạp vật (Harmless File Upload Inspector) này chỉ gửi huyễn ảnh đan thanh (Pure Harmless PNG), chớ nạp tà thuật kẻo thiên đạo tru diệt.
        for form, file_param_name in upload_forms:
            action = form.get("action", "") or endpoint.url
            target_post_url = urljoin(endpoint.url, action)

            # Đóng gói multipart form với file PNG vô hại đổi đuôi .php
            files = {
                file_param_name: (
                    "harmless_test_img.php",
                    cls.HARMLESS_PNG_BYTES,
                    "image/png",
                )
            }

            try:
                resp = http_client.session.post(
                    target_post_url,
                    files=files,
                    timeout=http_client.config.timeout,
                )

                # Đánh giá phản hồi: nếu server không từ chối (status 200/302) và không có thông báo lỗi định dạng
                body = (resp.text or "").lower()
                is_rejected = resp.status_code in (400, 403, 415) or any(
                    err in body for err in ["not allowed", "invalid extension", "chỉ cho phép", "không hợp lệ"]
                )

                if resp.status_code in (200, 302) and not is_rejected:
                    findings.append(Finding(
                        type="Unrestricted File Upload",
                        severity="HIGH",
                        status="WARNING",
                        detail=(
                            f"Form upload tại '{target_post_url}' đã chấp nhận tệp tin có đuôi .php "
                            "(nội dung tệp gửi thử nghiệm là ảnh PNG vô hại, không có mã thực thi). "
                            "Có dấu hiệu ứng dụng chỉ kiểm tra MIME type thay vì hạn chế nghiêm ngặt đuôi tệp."
                        ),
                        evidence=f"Action: {target_post_url} | File: harmless_test_img.php | HTTP {resp.status_code}",
                        confidence="MEDIUM",
                        recommendation=(
                            "Thiết lập whitelist đuôi tệp tin nghiêm ngặt (.png, .jpg, .pdf), "
                            "đổi tên tệp ngẫu nhiên khi lưu trữ và lưu ngoài thư mục web root."
                        ),
                        endpoint=endpoint.url,
                        payload_used="harmless_test_img.php (Valid PNG bytes)",
                    ))
            except ScanBudgetExceeded:
                raise
            except Exception:
                continue

        return findings
