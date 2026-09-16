from urllib.parse import urlparse
from typing import List, Optional
from models.finding import Finding
from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded

RISK_LEVEL = "safe"


class CORSCheck:
    """
    Kiểm tra CORS misconfiguration an toàn:
    - Sử dụng Origin vô hại: https://scanner-test-harmless.invalid (tránh evil.com bị WAF chặn).
    - Phân biệt rõ: '*', origin tin cậy, arbitrary reflection, và credentialed wildcard (ACAO=* + ACAC=true).
    """
    HARMLESS_TEST_ORIGIN = "https://scanner-test-harmless.invalid"
    NULL_ORIGIN = "null"

    # Đạo hữu xin nương tay, thông đạo giao thương (CORS Policy Check) này phân giải biên giới dị vực, chớ để tà đạo vượt rào thâm nhập.
    @classmethod
    def check(cls, endpoint_url: str, http_client: HTTPClient) -> List[Finding]:
        findings: List[Finding] = []

        parsed = urlparse(endpoint_url)
        target_origin = f"{parsed.scheme}://{parsed.netloc}"

        test_cases = [
            ("arbitrary", cls.HARMLESS_TEST_ORIGIN),
            ("null", cls.NULL_ORIGIN),
            ("trusted", target_origin),
        ]

        for case_type, test_origin in test_cases:
            try:
                resp = http_client.get(endpoint_url, headers={"Origin": test_origin})
                headers_lower = {k.lower(): str(v) for k, v in resp.headers.items()}
                acao = headers_lower.get("access-control-allow-origin", "").strip()
                acac = headers_lower.get("access-control-allow-credentials", "").strip().lower()

                if not acao:
                    continue

                is_credentialed = acac == "true"

                # 1. Trường hợp gửi arbitrary origin lạ
                if case_type == "arbitrary":
                    if acao == "*":
                        if is_credentialed:
                            findings.append(Finding(
                                type="Critical CORS Misconfiguration (Wildcard with Credentials)",
                                severity="CRITICAL",
                                status="VULNERABLE",
                                detail="Server cho phép Access-Control-Allow-Origin: * đi kèm Access-Control-Allow-Credentials: true.",
                                evidence=f"ACAO: {acao}, ACAC: {acac}",
                                confidence="HIGH",
                                recommendation="Tuyệt đối không dùng wildcard khi hỗ trợ gửi credentials (cookies/tokens).",
                                endpoint=endpoint_url,
                            ))
                        else:
                            findings.append(Finding(
                                type="Public CORS Wildcard",
                                severity="LOW",
                                status="INFO",
                                detail="Endpoint cho phép truy cập từ mọi Origin (ACAO: *) không kèm credentials.",
                                evidence=f"Access-Control-Allow-Origin: {acao}",
                                confidence="HIGH",
                                recommendation="Nếu là API công khai thì đây là hành vi bình thường. Nếu là dữ liệu nhạy cảm, hãy giới hạn Origin.",
                                endpoint=endpoint_url,
                            ))
                    elif acao.lower() == test_origin.lower():
                        # Arbitrary reflection: Server phản chiếu bất kỳ origin nào gửi lên!
                        if is_credentialed:
                            findings.append(Finding(
                                type="Critical CORS Misconfiguration (Arbitrary Origin Reflection with Credentials)",
                                severity="CRITICAL",
                                status="VULNERABLE",
                                detail=f"Server phản chiếu (reflect) Origin tùy ý từ kẻ tấn công kèm cờ Access-Control-Allow-Credentials: true.",
                                evidence=f"Request Origin: {test_origin} -> Response ACAO: {acao}, ACAC: {acac}",
                                confidence="HIGH",
                                recommendation="Thiết lập danh sách whitelist các Origin đáng tin cậy, không tin tưởng header Origin tùy ý.",
                                endpoint=endpoint_url,
                            ))
                        else:
                            findings.append(Finding(
                                type="CORS Arbitrary Origin Reflection",
                                severity="LOW",
                                status="WARNING",
                                detail="Server phản chiếu Origin gửi lên nhưng không cho phép credentials.",
                                evidence=f"Origin: {test_origin} -> ACAO: {acao}",
                                confidence="MEDIUM",
                                recommendation="Cân nhắc dùng whitelist cụ thể thay vì phản chiếu mọi Origin.",
                                endpoint=endpoint_url,
                            ))

                # 2. Trường hợp Origin là null
                elif case_type == "null" and acao.lower() == "null":
                    if is_credentialed:
                        findings.append(Finding(
                            type="Insecure CORS Null Origin with Credentials",
                            severity="HIGH",
                            status="VULNERABLE",
                            detail="Server tin tưởng Origin 'null' đi kèm credentials (có thể bị khai thác qua sandboxed iframe).",
                            evidence=f"ACAO: {acao}, ACAC: {acac}",
                            confidence="HIGH",
                            recommendation="Không cho phép Origin 'null' truy cập tài nguyên nhạy cảm có credentials.",
                            endpoint=endpoint_url,
                        ))
                    else:
                        findings.append(Finding(
                            type="CORS Null Origin Allowed",
                            severity="LOW",
                            status="WARNING",
                            detail="Server cho phép Origin 'null' truy cập.",
                            evidence=f"ACAO: {acao}",
                            confidence="MEDIUM",
                            endpoint=endpoint_url,
                        ))

            except ScanBudgetExceeded:
                raise
            except Exception:
                continue

        return findings
