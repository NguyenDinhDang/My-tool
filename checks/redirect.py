from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from typing import List

from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded
from models.finding import Finding

RISK_LEVEL = "active_only"


class OpenRedirectCheck:
    """
    Kiểm tra lỗ hổng Open Redirect (Active Mode Only):
    - Tìm kiếm các tham số điều hướng phổ biến (next, return, redirect, url, redirect_uri...).
    - Thử nghiệm bằng domain .invalid an toàn: https://scanner-redirect-test.invalid.
    - Phân biệt chuyển hướng nội bộ hợp lệ và chuyển hướng ngoài hoàn toàn.
    """

    REDIRECT_PARAMS = {
        "redirect", "url", "next", "return", "returnurl",
        "redirect_uri", "continue", "dest", "destination", "to", "goto", "target"
    }

    HARMLESS_EXTERNAL_TARGET = "https://scanner-redirect-test.invalid"

    @classmethod
    def check(
        cls,
        endpoint_url: str,
        http_client: HTTPClient,
        is_active_mode: bool = False,
    ) -> List[Finding]:
        if not is_active_mode or RISK_LEVEL != "active_only":
            return []

        findings: List[Finding] = []
        parsed = urlparse(endpoint_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return []

        # Đạo hữu xin nương tay, trận pháp di hình hoán ảnh (Open Redirect Analyzer) này phân định ranh giới giữa nội sơn và ngoại giới, chớ để linh thức lạc lối ngoài hồng trần.
        for p_idx, (p_name, p_val) in enumerate(params):
            if p_name.lower() not in cls.REDIRECT_PARAMS:
                continue

            mod_params = list(params)
            mod_params[p_idx] = (p_name, cls.HARMLESS_EXTERNAL_TARGET)
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
                # Không tự động follow redirect để đọc trực tiếp header Location
                resp = http_client.session.get(
                    test_url,
                    allow_redirects=False,
                    timeout=http_client.config.timeout,
                )

                location = resp.headers.get("Location", "").strip()
                status = resp.status_code

                if status in (301, 302, 303, 307, 308) and location:
                    loc_parsed = urlparse(location)

                    # Phân biệt chuyển hướng ngoài vs tương đối/nội bộ
                    is_open_redirect = False
                    if loc_parsed.netloc.lower() == "scanner-redirect-test.invalid":
                        is_open_redirect = True
                    elif location.startswith("//scanner-redirect-test.invalid"):
                        is_open_redirect = True

                    if is_open_redirect:
                        findings.append(Finding(
                            type="Open Redirect",
                            severity="MEDIUM",
                            status="VULNERABLE",
                            detail=(
                                f"Phát hiện lỗ hổng Open Redirect trên tham số '{p_name}'. "
                                f"Server trả về mã phản hồi {status} chuyển hướng trực tiếp ra domain ngoài không tin cậy."
                            ),
                            evidence=f"Status: {status} | Location: {location}",
                            confidence="HIGH",
                            recommendation=(
                                "Sử dụng whitelist cho danh sách URL được phép chuyển hướng, "
                                "hoặc chỉ cho phép các đường dẫn tương đối bắt đầu bằng một dấu gạch chéo '/'."
                            ),
                            endpoint=endpoint_url,
                            payload_used=cls.HARMLESS_EXTERNAL_TARGET,
                        ))
            except ScanBudgetExceeded:
                raise
            except Exception:
                continue

        return findings
