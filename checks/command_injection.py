import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from typing import List, Optional

from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded
from models.finding import Finding

RISK_LEVEL = "active_only"


class CommandInjectionCheck:
    """
    Kiểm tra lỗ hổng OS Command Injection hoàn toàn vô hại (Active Mode Only):
    - CHỈ dùng payload time-based vô hại: '; sleep 3' (Linux) / '& timeout 3' (Windows).
    - Đo độ trễ response so với baseline.
    - Tuyệt đối cấm: rm, del, format, shutdown, curl/wget, reverse shell.
    """

    SAFE_PAYLOADS = [
        ("Linux", "; sleep 3"),
        ("Windows", "& timeout 3"),
    ]

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

        # Đo baseline response time
        try:
            t_start = time.time()
            base_resp = http_client.get(endpoint_url)
            baseline_duration = time.time() - t_start
        except ScanBudgetExceeded:
            raise
        except Exception:
            return []

        # Đạo hữu xin nương tay, linh trận cảm ứng thời không (Time-based Baseline Matrix) này đang cân đo linh tức sai biệt, chớ dại nhiễu loạn thiên cơ kẻo cắn trả tẩu hỏa nhập ma.
        for param_idx, (p_name, p_val) in enumerate(params):
            param_vulnerable = False
            for os_type, payload in cls.SAFE_PAYLOADS:
                if param_vulnerable:
                    break

                mod_params = list(params)
                mod_params[param_idx] = (p_name, p_val + payload)
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
                    t0 = time.time()
                    resp = http_client.get(test_url)
                    elapsed = time.time() - t0

                    # Nếu thời gian phản hồi tăng xấp xỉ 3s so với baseline và đạt tối thiểu 2.5s
                    if elapsed >= 2.5 and (elapsed - baseline_duration) >= 2.0:
                        param_vulnerable = True
                        findings.append(Finding(
                            type="Command Injection",
                            severity="CRITICAL",
                            status="VULNERABLE",
                            detail=(
                                f"Phát hiện dấu hiệu Time-based OS Command Injection trên tham số '{p_name}'. "
                                f"Thời gian phản hồi tăng từ {round(baseline_duration, 2)}s lên {round(elapsed, 2)}s "
                                f"với payload vô hại ({os_type})."
                            ),
                            evidence=f"Baseline: {round(baseline_duration, 2)}s -> Test ({payload}): {round(elapsed, 2)}s",
                            confidence="HIGH",
                            recommendation=(
                                "Tuyệt đối không truyền tham số trực tiếp vào shell hoặc hệ thống. "
                                "Sử dụng shlex/subprocess với danh sách đối số độc lập hoặc API chuyên dụng."
                            ),
                            endpoint=endpoint_url,
                            payload_used=payload,
                        ))
                except ScanBudgetExceeded:
                    raise
                except Exception:
                    continue

        return findings
