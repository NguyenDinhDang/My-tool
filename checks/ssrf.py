import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from typing import List, Optional

from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded
from models.finding import Finding

RISK_LEVEL = "active_only"


class SSRFCheck:
    """
    Kiểm tra Server-Side Request Forgery (SSRF) có kiểm soát (Active Mode Only):
    - Cần callback_url được truyền tường minh qua cấu hình (--callback-url).
    - Nếu KHÔNG CÓ callback_url: trả về NOT_TESTED và dừng lại ngay.
    - TUYỆT ĐỐI KHÔNG tự ý thử 127.0.0.1 hay 169.254.169.254 (không hạ cấp check).
    """

    URL_PARAM_KEYWORDS = {
        "url", "target", "dest", "destination", "feed",
        "proxy", "webhook", "callback", "api", "fetch", "uri", "domain", "link"
    }

    @classmethod
    def check(
        cls,
        endpoint_url: str,
        http_client: HTTPClient,
        callback_url: Optional[str] = None,
        is_active_mode: bool = False,
    ) -> List[Finding]:
        if not is_active_mode or RISK_LEVEL != "active_only":
            return []

        parsed = urlparse(endpoint_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return []

        # Lọc các tham số tiềm năng nhận URL
        url_params = [
            (idx, p_name, p_val)
            for idx, (p_name, p_val) in enumerate(params)
            if p_name.lower() in cls.URL_PARAM_KEYWORDS
        ]
        if not url_params:
            return []

        # Đạo hữu xin nương tay, truyền âm vạn dặm (SSRF Out-of-band Gate) này cần có lệnh tiễn thông linh (Callback URL) mới được kích hoạt, chớ vượt quyền tự ý nghịch thiên.
        if not callback_url:
            return [
                Finding(
                    type="SSRF",
                    severity="INFO",
                    status="NOT_TESTED",
                    detail=(
                        f"Phát hiện tham số tiềm năng '{url_params[0][1]}' có thể nhận URL, "
                        "nhưng chưa được cấu hình --callback-url. Theo nguyên tắc an toàn số 4, "
                        "scanner không tự ý thử nghiệm địa chỉ nội bộ (127.0.0.1/169.254.169.254)."
                    ),
                    evidence="Thiếu cờ --callback-url",
                    confidence="LOW",
                    recommendation="Cung cấp máy chủ callback an toàn thông qua cờ --callback-url để tiến hành kiểm tra out-of-band.",
                    endpoint=endpoint_url,
                )
            ]

        findings: List[Finding] = []
        for p_idx, p_name, _ in url_params:
            mod_params = list(params)
            mod_params[p_idx] = (p_name, callback_url)
            new_query = urlencode(mod_params)
            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            ))

            try:
                resp = http_client.get(test_url)
                # Đã dispatch request trỏ tới callback an toàn
                findings.append(Finding(
                    type="SSRF Probe",
                    severity="MEDIUM",
                    status="WARNING",
                    detail=(
                        f"Đã gửi payload kiểm tra SSRF qua tham số '{p_name}' trỏ tới callback URL đã chỉ định. "
                        "Vui lòng kiểm tra log trên máy chủ callback để xác nhận xem có HTTP request gửi từ máy chủ mục tiêu không."
                    ),
                    evidence=f"Payload gửi tới: {callback_url} | HTTP Status: {resp.status_code}",
                    confidence="MEDIUM",
                    recommendation="Áp dụng Whitelist URL cho phép truy cập, chặn hoàn toàn truy cập vào dải IP private/metadata.",
                    endpoint=endpoint_url,
                    payload_used=callback_url,
                ))
            except ScanBudgetExceeded:
                raise
            except Exception:
                continue

        return findings
