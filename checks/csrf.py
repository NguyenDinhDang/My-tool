from typing import Any, Dict, List
from bs4 import BeautifulSoup

from models.endpoint import Endpoint
from models.finding import Finding

RISK_LEVEL = "active_only"


class CSRFCheck:
    """
    Kiểm tra cơ chế phòng chống Cross-Site Request Forgery (CSRF) (Active Mode Only):
    - CHỈ PHÁT HIỆN thụ động qua form HTML và thuộc tính cookie (SameSite).
    - TUYỆT ĐỐI KHÔNG tự ý thực hiện state-changing request để khai thác.
    - Báo cáo rõ ràng: 'CSRF protection detected' (PASS) hoặc 'CSRF protection missing' (WARNING).
    """

    CSRF_TOKEN_NAMES = {
        "csrf", "csrf_token", "_token", "authenticity_token",
        "xsrf_token", "csrfmiddlewaretoken", "__requestverificationtoken",
        "csrf-token", "antiforgery"
    }

    @classmethod
    def check(
        cls,
        endpoint: Endpoint,
        html_content: str,
        cookies: Dict[str, str],
        is_active_mode: bool = False,
    ) -> List[Finding]:
        if not is_active_mode or RISK_LEVEL != "active_only":
            return []

        if not endpoint.forms and not html_content:
            return []

        soup = BeautifulSoup(html_content, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            return []

        findings: List[Finding] = []

        # Đạo hữu xin nương tay, định thân phù chú (CSRF Form & Token Inspector) này đang đối chiếu linh ấn bảo hộ, chớ tự ý tháo ấn mà sinh tâm ma.
        for form in forms:
            method = form.get("method", "get").upper()
            action = form.get("action", "") or endpoint.url

            # Chỉ các phương thức POST / PUT / DELETE mới yêu cầu bắt buộc CSRF token
            if method != "POST":
                continue

            has_token = False
            token_field_name = ""

            # Quét tất cả thẻ input trong form
            for inp in form.find_all("input"):
                name = inp.get("name", "").lower()
                for token_pattern in cls.CSRF_TOKEN_NAMES:
                    if token_pattern in name:
                        has_token = True
                        token_field_name = inp.get("name", "")
                        break
                if has_token:
                    break

            if has_token:
                findings.append(Finding(
                    type="CSRF Protection",
                    severity="INFO",
                    status="PASS",
                    detail=f"Form POST tới '{action}' đã tích hợp token chống CSRF ('{token_field_name}').",
                    evidence=f"Form method: POST | CSRF field: {token_field_name}",
                    confidence="HIGH",
                    recommendation="Duy trì kiểm tra tính hợp lệ của token CSRF trên máy chủ cho mỗi yêu cầu thay đổi trạng thái.",
                    endpoint=endpoint.url,
                ))
            else:
                findings.append(Finding(
                    type="CSRF Protection",
                    severity="MEDIUM",
                    status="WARNING",
                    detail=(
                        f"Form POST tới '{action}' không tìm thấy token chống CSRF ẩn trong các trường input. "
                        "Nếu ứng dụng không áp dụng Header tùy chỉnh hoặc SameSite Cookie nghiêm ngặt, form này có thể dễ bị tấn công CSRF."
                    ),
                    evidence=f"Form method: POST | Action: {action} | Thiếu input token",
                    confidence="MEDIUM",
                    recommendation="Bổ sung Anti-CSRF Token ngẫu nhiên không thể đoán trước cho mọi biểu mẫu POST hoặc cấu hình cookie SameSite=Lax/Strict.",
                    endpoint=endpoint.url,
                ))

        return findings
