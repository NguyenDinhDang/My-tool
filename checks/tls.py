from datetime import datetime, timezone
import socket
import ssl
from urllib.parse import urlparse
from typing import List
from models.finding import Finding
from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded

RISK_LEVEL = "safe"


class TLSCheck:
    """
    Kiểm tra TLS/SSL:
    1. Chuyển hướng tự động từ HTTP sang HTTPS.
    2. Trạng thái và tính hợp lệ của chứng chỉ số SSL/TLS (hạn dùng, CA verify).
    KHÔNG tắt verify cert để lách lỗi — nếu cert lỗi thì đó chính là finding.
    """

    # Đạo hữu xin nương tay, thiên kiếp hộ thể (TLS/SSL Certification Check) này kiểm chứng đạo hạnh kết nối, chớ làm đứt gãy thần giao kẻo rơi vào hư vô.
    @classmethod
    def check(cls, target_url: str, http_client: HTTPClient) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        if not hostname:
            return findings

        # 1. Kiểm tra chuyển hướng HTTP sang HTTPS nếu target là HTTP
        if parsed.scheme == "http" and hostname not in ("localhost", "127.0.0.1"):
            try:
                resp = http_client.get(target_url, allow_redirects=False)
                loc = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 307, 308) and loc.startswith("https://"):
                    findings.append(Finding(
                        type="HTTP to HTTPS Redirection",
                        severity="INFO",
                        status="PASS",
                        detail="Trang web tự động chuyển hướng từ HTTP sang HTTPS.",
                        evidence=f"Status: {resp.status_code}, Location: {loc}",
                        confidence="HIGH",
                        endpoint=target_url,
                    ))
                else:
                    findings.append(Finding(
                        type="Missing HTTP to HTTPS Redirection",
                        severity="MEDIUM",
                        status="VULNERABLE",
                        detail="Trang web không tự động chuyển hướng từ kết nối HTTP không mã hóa sang HTTPS.",
                        evidence=f"Status: {resp.status_code}, Location: {loc or 'None'}",
                        confidence="HIGH",
                        recommendation="Cấu hình web server redirect 301 vĩnh viễn từ HTTP sang HTTPS.",
                        endpoint=target_url,
                    ))
            except ScanBudgetExceeded:
                raise
            except Exception:
                pass

        # 2. Kiểm tra chứng chỉ SSL/TLS bằng module ssl
        port = parsed.port or (443 if parsed.scheme == "https" else None)
        if parsed.scheme == "https" and port and hostname not in ("localhost", "127.0.0.1"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            try:
                with socket.create_connection((hostname, port), timeout=5.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        not_after_str = cert.get("notAfter")
                        if not_after_str:
                            # Định dạng thời gian cert: 'May 15 12:00:00 2026 GMT'
                            expire_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            days_remaining = (expire_date - now).days

                            if days_remaining < 0:
                                findings.append(Finding(
                                    type="Expired SSL Certificate",
                                    severity="HIGH",
                                    status="VULNERABLE",
                                    detail=f"Chứng chỉ SSL/TLS đã hết hạn từ {abs(days_remaining)} ngày trước ({not_after_str}).",
                                    evidence=f"notAfter: {not_after_str}",
                                    confidence="HIGH",
                                    recommendation="Gia hạn chứng chỉ SSL/TLS ngay lập tức.",
                                    endpoint=f"https://{hostname}:{port}",
                                ))
                            elif days_remaining < 30:
                                findings.append(Finding(
                                    type="Expiring SSL Certificate",
                                    severity="LOW",
                                    status="WARNING",
                                    detail=f"Chứng chỉ SSL/TLS sắp hết hạn trong vòng {days_remaining} ngày ({not_after_str}).",
                                    evidence=f"notAfter: {not_after_str}",
                                    confidence="HIGH",
                                    recommendation="Lên kế hoạch gia hạn chứng chỉ SSL trước khi hết hạn.",
                                    endpoint=f"https://{hostname}:{port}",
                                ))
                            else:
                                findings.append(Finding(
                                    type="Valid SSL Certificate",
                                    severity="INFO",
                                    status="PASS",
                                    detail=f"Chứng chỉ SSL/TLS hợp lệ và còn hạn {days_remaining} ngày.",
                                    evidence=f"notAfter: {not_after_str}",
                                    confidence="HIGH",
                                    endpoint=f"https://{hostname}:{port}",
                                ))

            except ssl.SSLCertVerificationError as e:
                findings.append(Finding(
                    type="Invalid SSL Certificate",
                    severity="HIGH",
                    status="VULNERABLE",
                    detail=f"Chứng chỉ SSL/TLS không hợp lệ hoặc không được tin cậy (CA không rõ hoặc self-signed): {str(e)}",
                    evidence=str(e),
                    confidence="HIGH",
                    recommendation="Cài đặt chứng chỉ SSL/TLS được cấp bởi một Certificate Authority (CA) hợp lệ.",
                    endpoint=f"https://{hostname}:{port}",
                ))
            except Exception as e:
                findings.append(Finding(
                    type="TLS Connection Error",
                    severity="LOW",
                    status="INFO",
                    detail=f"Không thể hoàn tất bắt tay TLS tới {hostname}:{port}: {str(e)}",
                    evidence=str(e),
                    confidence="MEDIUM",
                    endpoint=f"https://{hostname}:{port}",
                ))

        return findings
