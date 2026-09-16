from typing import Dict, List, Optional
from models.finding import Finding
from core.response import Response

RISK_LEVEL = "safe"


class HeadersCheck:
    """
    Kiểm tra các security headers trên HTTP response.
    Phân loại chính xác PASS/WARNING/VULNERABLE/INFO, KHÔNG mặc định 'thiếu = Critical'.
    """

    # Đạo hữu xin nương tay, môn quy hộ thuẫn (Security Headers Analysis) này điều tức các tầng phòng thủ ngoại vi, chớ dại phán bừa kẻo làm kinh động chư vị trưởng lão.
    @classmethod
    def check(cls, response: Response, target_url: str) -> List[Finding]:
        findings: List[Finding] = []
        headers = {k.lower(): str(v) for k, v in response.headers.items()}
        content_type = headers.get("content-type", "").lower()

        # Chỉ kiểm tra headers chính trên các response phục vụ HTML hoặc API
        is_html = "text/html" in content_type
        endpoint = response.url or target_url

        # 1. Content-Security-Policy (CSP)
        csp = headers.get("content-security-policy")
        if csp:
            if "unsafe-inline" in csp or "unsafe-eval" in csp or "*" in csp:
                findings.append(Finding(
                    type="Weak Content-Security-Policy",
                    severity="LOW",
                    status="WARNING",
                    detail="Content-Security-Policy chứa chỉ thị yếu ('unsafe-inline', 'unsafe-eval' hoặc '*').",
                    evidence=f"Content-Security-Policy: {csp[:100]}...",
                    confidence="HIGH",
                    recommendation="Loại bỏ 'unsafe-inline' và 'unsafe-eval', dùng nonce hoặc sha256 hash cho scripts.",
                    endpoint=endpoint,
                ))
            else:
                findings.append(Finding(
                    type="Content-Security-Policy",
                    severity="INFO",
                    status="PASS",
                    detail="Content-Security-Policy được cấu hình chặt chẽ.",
                    evidence=f"Content-Security-Policy: {csp[:80]}...",
                    confidence="HIGH",
                    recommendation="Duy trì chính sách CSP hiện tại.",
                    endpoint=endpoint,
                ))
        elif is_html:
            findings.append(Finding(
                type="Missing Content-Security-Policy",
                severity="MEDIUM",
                status="VULNERABLE",
                detail="Thiếu header Content-Security-Policy (CSP) giúp ngăn chặn tấn công XSS và Data Injection.",
                evidence="Không tìm thấy header Content-Security-Policy",
                confidence="HIGH",
                recommendation="Thiết lập Content-Security-Policy (ví dụ: default-src 'self').",
                endpoint=endpoint,
            ))

        # 2. Strict-Transport-Security (HSTS)
        hsts = headers.get("strict-transport-security")
        is_https = endpoint.startswith("https://")
        if is_https:
            if not hsts:
                findings.append(Finding(
                    type="Missing Strict-Transport-Security",
                    severity="MEDIUM",
                    status="VULNERABLE",
                    detail="Trang web HTTPS nhưng thiếu header Strict-Transport-Security (HSTS).",
                    evidence="Không tìm thấy header Strict-Transport-Security",
                    confidence="HIGH",
                    recommendation="Thêm header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    endpoint=endpoint,
                ))
            else:
                findings.append(Finding(
                    type="Strict-Transport-Security",
                    severity="INFO",
                    status="PASS",
                    detail="HSTS được bật cho kết nối HTTPS.",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    confidence="HIGH",
                    endpoint=endpoint,
                ))

        # 3. X-Content-Type-Options
        xcto = headers.get("x-content-type-options")
        if xcto and "nosniff" in xcto.lower():
            findings.append(Finding(
                type="X-Content-Type-Options",
                severity="INFO",
                status="PASS",
                detail="X-Content-Type-Options được cấu hình nosniff đúng cách.",
                evidence=f"X-Content-Type-Options: {xcto}",
                confidence="HIGH",
                endpoint=endpoint,
            ))
        else:
            findings.append(Finding(
                type="Missing X-Content-Type-Options",
                severity="LOW",
                status="WARNING",
                detail="Thiếu X-Content-Type-Options: nosniff khiến trình duyệt có thể MIME-sniffing file ngoài ý muốn.",
                evidence="Không tìm thấy X-Content-Type-Options: nosniff",
                confidence="HIGH",
                recommendation="Thêm header: X-Content-Type-Options: nosniff",
                endpoint=endpoint,
            ))

        # 4. X-Frame-Options
        xfo = headers.get("x-frame-options")
        if is_html:
            if xfo and any(opt in xfo.lower() for opt in ["deny", "sameorigin"]):
                findings.append(Finding(
                    type="X-Frame-Options",
                    severity="INFO",
                    status="PASS",
                    detail="X-Frame-Options ngăn chặn Clickjacking hiệu quả.",
                    evidence=f"X-Frame-Options: {xfo}",
                    confidence="HIGH",
                    endpoint=endpoint,
                ))
            elif not csp or "frame-ancestors" not in csp:
                findings.append(Finding(
                    type="Missing Anti-Clickjacking Header",
                    severity="MEDIUM",
                    status="WARNING",
                    detail="Thiếu X-Frame-Options hoặc CSP frame-ancestors, có nguy cơ bị Clickjacking.",
                    evidence="Không có X-Frame-Options hoặc frame-ancestors",
                    confidence="HIGH",
                    recommendation="Thêm X-Frame-Options: SAMEORIGIN hoặc CSP frame-ancestors 'self'.",
                    endpoint=endpoint,
                ))

        # 5. Referrer-Policy
        ref = headers.get("referrer-policy")
        if not ref:
            findings.append(Finding(
                type="Missing Referrer-Policy",
                severity="LOW",
                status="INFO",
                detail="Chưa cấu hình Referrer-Policy để giới hạn rò rỉ URL qua Referer header.",
                evidence="Không tìm thấy header Referrer-Policy",
                confidence="MEDIUM",
                recommendation="Thêm Referrer-Policy: strict-origin-when-cross-origin",
                endpoint=endpoint,
            ))

        # 6. Permissions-Policy
        perm = headers.get("permissions-policy") or headers.get("feature-policy")
        if not perm and is_html:
            findings.append(Finding(
                type="Missing Permissions-Policy",
                severity="LOW",
                status="INFO",
                detail="Thiếu Permissions-Policy kiểm soát các tính năng phần cứng/trình duyệt (camera, geolocation).",
                evidence="Không tìm thấy header Permissions-Policy",
                confidence="LOW",
                recommendation="Cân nhắc thêm Permissions-Policy: camera=(), microphone=(), geolocation=()",
                endpoint=endpoint,
            ))

        # 7. Cross-Origin Headers (COOP, CORP, COEP)
        coop = headers.get("cross-origin-opener-policy")
        if not coop and is_html:
            findings.append(Finding(
                type="Missing Cross-Origin-Opener-Policy",
                severity="LOW",
                status="INFO",
                detail="Thiếu Cross-Origin-Opener-Policy (COOP) để cô lập ngữ cảnh duyệt web.",
                evidence="Không tìm thấy Cross-Origin-Opener-Policy",
                confidence="LOW",
                recommendation="Cân nhắc thêm Cross-Origin-Opener-Policy: same-origin",
                endpoint=endpoint,
            ))

        return findings
