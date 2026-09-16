import json
from typing import Any, Dict, List, Optional
from models.finding import Finding
from models.endpoint import Endpoint
from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded

RISK_LEVEL = "safe"


class NoSQLICheck:
    """
    Kiểm tra NoSQL Injection (Operator Injection an toàn):
    - CHỈ test trên JSON endpoint đã crawl được (content-type application/json).
    - Thử toán tử an toàn: {"$ne": None} hoặc {"$gt": ""} để xem response có khác biệt so với baseline.
    - TUYỆT ĐỐI KHÔNG cố gắng bypass auth hay brute-force hàng loạt.
    - Dừng ngay trên trường đó khi có bằng chứng đầu tiên.
    """

    # Đạo hữu xin nương tay, hư vô chuyển hoán thuật (NoSQL Operator Check) này chỉ thăm dò phản ứng của kho tàng dữ liệu JSON phi quan hệ, chớ ép cung quá đà kẻo loạn linh trận.
    @classmethod
    def check_json_endpoint(cls, endpoint: Endpoint, http_client: HTTPClient) -> List[Finding]:
        findings: List[Finding] = []

        # Chỉ áp dụng nếu content-type là application/json hoặc endpoint có tham số
        is_json_endpoint = "application/json" in endpoint.content_type.lower() or any(
            p.lower() in ("json", "data", "filter", "query", "user", "username") for p in endpoint.parameters
        )

        if not is_json_endpoint or not endpoint.parameters:
            return findings

        # 1. Đo baseline ban đầu
        try:
            baseline_resp = http_client.get(endpoint.url)
            baseline_status = baseline_resp.status_code
            baseline_len = len(baseline_resp.text or "")
        except ScanBudgetExceeded:
            raise
        except Exception:
            return findings

        # Thử toán tử NoSQL an toàn trên từng tham số (tối đa 1 lần mỗi tham số)
        for param in endpoint.parameters[:5]:
            # Thử gửi payload JSON với $ne (not equal)
            operator_payload = {param: {"$ne": None}}

            try:
                # Gửi request POST JSON để thăm dò
                test_resp = http_client.post(
                    endpoint.url,
                    json=operator_payload,
                    headers={"Content-Type": "application/json"}
                )
                test_len = len(test_resp.text or "")

                # Phân tích sự khác biệt an toàn:
                # Nếu request chứa operator $ne trả về status 200 trong khi baseline bị từ chối (400/401/403/422),
                # hoặc kích thước phản hồi tăng vọt đáng kể (do trả về nhiều bản ghi không mong muốn)
                if (
                    (baseline_status in (400, 401, 403, 404, 422) and test_resp.status_code == 200)
                    or (test_resp.status_code == 200 and test_len > baseline_len + 150)
                ):
                    findings.append(Finding(
                        type="NoSQL Injection (Operator Injection)",
                        severity="HIGH",
                        status="VULNERABLE",
                        detail=(
                            f"Endpoint chấp nhận cấu trúc toán tử NoSQL ('$ne') qua trường '{param}'. "
                            f"Trạng thái hoặc nội dung phản hồi thay đổi rõ rệt so với baseline."
                        ),
                        evidence=(
                            f"Field: {param} | Payload: {json.dumps(operator_payload)} | "
                            f"Baseline: [Status {baseline_status}, Len {baseline_len}] -> Test: [Status {test_resp.status_code}, Len {test_len}]"
                        ),
                        confidence="MEDIUM",
                        recommendation="Sanitize và ép kiểu dữ liệu đầu vào (string/int), từ chối các object chứa key bắt đầu bằng '$'.",
                        endpoint=endpoint.url,
                        payload_used=json.dumps(operator_payload),
                    ))
                    # Dừng ngay khi có evidence đầu tiên trên endpoint này
                    break

            except ScanBudgetExceeded:
                raise
            except Exception:
                continue

        return findings
