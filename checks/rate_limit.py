from typing import List

from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded
from models.finding import Finding

RISK_LEVEL = "active_only"


class RateLimitCheck:
    """
    Kiểm tra cơ chế hạn chế tần suất yêu cầu (Rate Limiting) (Active Mode Only):
    - Tối đa 5 request liên tiếp lên CÙNG 1 endpoint.
    - Dừng sớm nếu đã phát hiện status 429 hoặc RateLimit headers ở request thứ 2-3.
    - Tuyệt đối không kết luận 'No rate limiting' thiếu căn cứ: ghi rõ không mang tính kết luận tuyệt đối.
    """

    MAX_BURST_REQUESTS = 5

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
        hit_429 = False
        rate_limit_headers = []
        requests_sent = 0

        # Đạo hữu xin nương tay, liên hoàn ngũ kích (Rate Limit Burst Probe) này chỉ thử nghiệm 5 chiêu thăm dò khí tức, chớ dại dồn sức bạo kích kẻo trận đồ đối phương phong tỏa.
        for i in range(cls.MAX_BURST_REQUESTS):
            requests_sent += 1
            try:
                # Gửi request nhanh không qua delay rate limiter nội bộ nếu muốn test burst
                resp = http_client.session.get(endpoint_url, timeout=http_client.config.timeout)

                # Kiểm tra headers rate limit
                for h in ["retry-after", "x-ratelimit-remaining", "x-ratelimit-limit", "ratelimit-remaining"]:
                    if h in resp.headers:
                        rate_limit_headers.append(f"{h}: {resp.headers[h]}")

                if resp.status_code == 429:
                    hit_429 = True
                    # Dừng sớm ngay khi phát hiện 429
                    break

            except ScanBudgetExceeded:
                raise
            except Exception:
                break

        if hit_429 or rate_limit_headers:
            evidence_str = f"Status: 429 ở request thứ {requests_sent}" if hit_429 else f"Headers: {', '.join(set(rate_limit_headers))}"
            findings.append(Finding(
                type="Rate Limiting",
                severity="INFO",
                status="PASS",
                detail=f"Phát hiện cơ chế giới hạn tần suất yêu cầu (Rate Limiting) trên '{endpoint_url}'.",
                evidence=evidence_str,
                confidence="HIGH",
                recommendation="Tiếp tục duy trì cấu hình rate limit hợp lý trên các tài nguyên quan trọng.",
                endpoint=endpoint_url,
            ))
        else:
            findings.append(Finding(
                type="Rate Limiting",
                severity="LOW",
                status="INFO",
                detail=(
                    f"Không ghi nhận phản hồi HTTP 429 hay header giới hạn sau {requests_sent} request thử nghiệm nhanh. "
                    "Lưu ý: Không thể kết luận hệ thống thiếu rate limiting chỉ qua 5 request thử nghiệm (not conclusive)."
                ),
                evidence=f"Đã gửi {requests_sent} request liên tiếp | HTTP status không đổi",
                confidence="LOW",
                recommendation="Đảm bảo cấu hình Rate Limiting ở tầng Reverse Proxy hoặc WAF đối với các tài nguyên nhạy cảm.",
                endpoint=endpoint_url,
            ))

        return findings
