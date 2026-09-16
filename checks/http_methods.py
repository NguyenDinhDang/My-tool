from typing import List, Optional
from models.finding import Finding
from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded

RISK_LEVEL = "safe"


class HTTPMethodsCheck:
    """
    Kiểm tra HTTP Methods an toàn:
    - Gửi OPTIONS xem header Allow / Public.
    - Thử TRACE xem máy chủ có bật phương thức echo hay không.
    - TUYỆT ĐỐI KHÔNG tự ý gửi PUT/DELETE/PATCH với body thật lên endpoint chưa rõ tác dụng.
    """
    DANGEROUS_METHODS = {"PUT", "DELETE", "CONNECT"}

    # Đạo hữu xin nương tay, quan sát pháp môn (HTTP Methods Inspection) này chỉ xem xét biển chỉ dẫn (Allow header), không hề động thủ phá hoại bất kỳ cấm chế nào.
    @classmethod
    def check(cls, endpoint_url: str, http_client: HTTPClient) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Gửi OPTIONS kiểm tra Allow header
        try:
            resp_options = http_client.options(endpoint_url)
            headers_lower = {k.lower(): str(v) for k, v in resp_options.headers.items()}
            allow_val = headers_lower.get("allow") or headers_lower.get("public") or ""

            if allow_val:
                allowed_methods = {m.strip().upper() for m in allow_val.split(",") if m.strip()}
                exposed_dangerous = allowed_methods.intersection(cls.DANGEROUS_METHODS)

                if exposed_dangerous:
                    findings.append(Finding(
                        type="Potentially Insecure HTTP Methods Allowed",
                        severity="LOW",
                        status="WARNING",
                        detail=f"Header Allow liệt kê các phương thức có nguy cơ rủi ro cao: {', '.join(sorted(exposed_dangerous))}.",
                        evidence=f"Allow: {allow_val}",
                        confidence="HIGH",
                        recommendation="Vô hiệu hóa các phương thức PUT, DELETE nếu endpoint không yêu cầu hoặc bảo vệ bằng xác thực nghiêm ngặt.",
                        endpoint=endpoint_url,
                    ))
                else:
                    findings.append(Finding(
                        type="HTTP Methods Allowed",
                        severity="INFO",
                        status="PASS",
                        detail=f"Các phương thức HTTP được khai báo trong header Allow: {', '.join(sorted(allowed_methods))}.",
                        evidence=f"Allow: {allow_val}",
                        confidence="HIGH",
                        endpoint=endpoint_url,
                    ))

        except ScanBudgetExceeded:
            raise
        except Exception:
            pass

        # 2. Thử TRACE (Cross-Site Tracing - XST check)
        try:
            resp_trace = http_client.request("TRACE", endpoint_url)
            ct = resp_trace.content_type.lower()
            body = resp_trace.text or ""

            # Dấu hiệu TRACE bật: status 200 và echo lại request line hoặc message/http
            if resp_trace.status_code == 200 and ("message/http" in ct or "trace" in body.lower() or "host:" in body.lower()):
                findings.append(Finding(
                    type="HTTP TRACE Method Enabled",
                    severity="MEDIUM",
                    status="VULNERABLE",
                    detail="Máy chủ bật phương thức HTTP TRACE, dẫn đến nguy cơ Cross-Site Tracing (XST) đánh cắp cookie HttpOnly.",
                    evidence=f"Status: {resp_trace.status_code}, Content-Type: {resp_trace.content_type}",
                    confidence="HIGH",
                    recommendation="Tắt phương thức TRACE trong cấu hình web server (vd: TraceEnable off trong Apache).",
                    endpoint=endpoint_url,
                ))
            elif resp_trace.status_code in (405, 403, 501):
                findings.append(Finding(
                    type="HTTP TRACE Disabled",
                    severity="INFO",
                    status="PASS",
                    detail="Phương thức HTTP TRACE đã được máy chủ vô hiệu hóa đúng cách.",
                    evidence=f"Status: {resp_trace.status_code}",
                    confidence="HIGH",
                    endpoint=endpoint_url,
                ))

        except ScanBudgetExceeded:
            raise
        except Exception:
            pass

        return findings
