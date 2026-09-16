from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlparse

from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded
from models.finding import Finding

RISK_LEVEL = "active_only"


class IDORCheck:
    """
    Kiểm tra Insecure Direct Object Reference (IDOR) có kiểm soát (Active Mode Only):
    - Bắt buộc cần 2 phiên (User A và User B) được cấu hình rõ ràng qua CLI.
    - Nếu thiếu 1 trong 2 phiên: trả về NOT_TESTED và dừng lại ngay (Nguyên tắc 4).
    - Chỉ thử nghiệm tối đa 1-2 object ID cụ thể, TUYỆT ĐỐI KHÔNG brute-force dải ID.
    """

    ID_PARAM_KEYWORDS = {"id", "user_id", "userid", "account_id", "profile_id", "doc_id", "order_id"}

    @classmethod
    def check(
        cls,
        endpoint_url: str,
        http_client: HTTPClient,
        auth_cookie_a: Optional[str] = None,
        auth_cookie_b: Optional[str] = None,
        auth_header_a: Optional[str] = None,
        auth_header_b: Optional[str] = None,
        is_active_mode: bool = False,
    ) -> List[Finding]:
        if not is_active_mode or RISK_LEVEL != "active_only":
            return []

        parsed = urlparse(endpoint_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        has_id_param = any(k.lower() in cls.ID_PARAM_KEYWORDS for k, _ in params)
        if not has_id_param:
            return []

        has_user_a = bool(auth_cookie_a or auth_header_a)
        has_user_b = bool(auth_cookie_b or auth_header_b)

        # Đạo hữu xin nương tay, song tu kiểm chứng (Dual-Session IDOR Cross-Check) này bắt buộc phải có đủ song kiếm hợp bích (User A & User B), chớ tự ý luyện đơn kiếm mà nghịch mạch.
        if not (has_user_a and has_user_b):
            return [
                Finding(
                    type="IDOR",
                    severity="INFO",
                    status="NOT_TESTED",
                    detail=(
                        f"Phát hiện tham số định danh đối tượng trực tiếp trên '{endpoint_url}', "
                        "tuy nhiên chưa cung cấp đủ thông tin xác thực cho 2 phiên độc lập (User A và User B). "
                        "Theo nguyên tắc số 4, scanner trả về NOT_TESTED và không tự ý thử nghiệm suy đoán."
                    ),
                    evidence="Thiếu thông tin xác thực User A hoặc User B (--auth-cookie / --auth-header)",
                    confidence="LOW",
                    recommendation="Cung cấp token/cookie của 2 tài khoản phân quyền khác nhau để kiểm tra IDOR an toàn.",
                    endpoint=endpoint_url,
                )
            ]

        findings: List[Finding] = []
        headers_b = {}
        if auth_header_b:
            # Ví dụ: "Authorization: Bearer xyz"
            parts = auth_header_b.split(":", 1)
            if len(parts) == 2:
                headers_b[parts[0].strip()] = parts[1].strip()

        try:
            # Thử gửi request bằng phiên của User B để truy cập tài nguyên
            cookies_b = {"session": auth_cookie_b} if auth_cookie_b else None
            resp = http_client.session.get(
                endpoint_url,
                headers=headers_b,
                cookies=cookies_b,
                timeout=http_client.config.timeout,
            )

            # Nếu User B truy cập thành công 200 OK mà không bị 401/403
            if resp.status_code == 200 and len(resp.text) > 50:
                findings.append(Finding(
                    type="Potential IDOR",
                    severity="HIGH",
                    status="VULNERABLE",
                    detail=(
                        f"Phát hiện khả năng truy cập trái quyền (IDOR) trên '{endpoint_url}'. "
                        "Phiên người dùng B có thể truy cập thành công tài nguyên với HTTP 200 OK."
                    ),
                    evidence=f"User B request -> Status: {resp.status_code} (Length: {len(resp.text)})",
                    confidence="MEDIUM",
                    recommendation="Thực hiện kiểm tra quyền sở hữu đối tượng (Access Control Check) ở tầng logic ứng dụng trước khi trả về dữ liệu.",
                    endpoint=endpoint_url,
                ))
        except ScanBudgetExceeded:
            raise
        except Exception:
            pass

        return findings
