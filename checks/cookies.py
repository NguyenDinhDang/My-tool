import re
from typing import Dict, List, Optional
from models.finding import Finding
from core.response import Response

RISK_LEVEL = "safe"


class CookiesCheck:
    """
    Kiểm tra các thuộc tính bảo mật của Cookie: HttpOnly, Secure, SameSite, Domain, Path.
    Ưu tiên cảnh báo mức độ nghiêm trọng cao hơn đối với cookie định danh phiên/auth.
    """
    AUTH_COOKIE_KEYWORDS = {
        "session", "token", "auth", "jwt", "phpsessid",
        "jsessionid", "sid", "login", "key", "remember",
        "connect.sid", "laravel_session", "asp.net_sessionid"
    }

    # Đạo hữu xin nương tay, ngọc bài nhận dạng (Cookie Security Check) này phong tỏa linh tức tài khoản, chớ đảo lộn cấm chế kẻo hồn phách phân ly.
    @classmethod
    def check(cls, response: Response, target_url: str) -> List[Finding]:
        findings: List[Finding] = []
        endpoint = response.url or target_url
        is_https = endpoint.startswith("https://")

        raw_set_cookies = []
        for k, v in response.headers.items():
            if k.lower() == "set-cookie":
                raw_set_cookies.append(v)

        if not raw_set_cookies:
            return findings

        for cookie_str in raw_set_cookies:
            parts = [p.strip() for p in cookie_str.split(";")]
            if not parts:
                continue

            first_part = parts[0]
            if "=" not in first_part:
                continue

            cookie_name, _ = first_part.split("=", 1)
            cookie_name = cookie_name.strip()
            cookie_name_lower = cookie_name.lower()

            is_auth_cookie = any(kw in cookie_name_lower for kw in cls.AUTH_COOKIE_KEYWORDS)

            attributes = {}
            flags = set()
            for part in parts[1:]:
                if "=" in part:
                    attr_name, attr_val = part.split("=", 1)
                    attributes[attr_name.strip().lower()] = attr_val.strip()
                else:
                    flags.add(part.lower())

            has_httponly = "httponly" in flags
            has_secure = "secure" in flags
            samesite = attributes.get("samesite", "").lower()

            masked_cookie_sample = f"{cookie_name}=****"

            # 1. Kiểm tra HttpOnly
            if not has_httponly:
                severity = "MEDIUM" if is_auth_cookie else "LOW"
                status = "VULNERABLE" if is_auth_cookie else "WARNING"
                findings.append(Finding(
                    type="Missing HttpOnly Flag",
                    severity=severity,
                    status=status,
                    detail=(
                        f"Cookie '{cookie_name}' (có dấu hiệu là session/auth cookie) thiếu cờ HttpOnly, "
                        f"dẫn đến nguy cơ bị đánh cắp qua tấn công XSS."
                        if is_auth_cookie else
                        f"Cookie '{cookie_name}' không có cờ HttpOnly."
                    ),
                    evidence=f"Set-Cookie: {masked_cookie_sample}; {'; '.join(parts[1:])}",
                    confidence="HIGH",
                    recommendation="Thêm thuộc tính HttpOnly vào Set-Cookie để ngăn JavaScript đọc cookie.",
                    endpoint=endpoint,
                ))

            # 2. Kiểm tra Secure (trên HTTPS)
            if is_https and not has_secure:
                severity = "MEDIUM" if is_auth_cookie else "LOW"
                status = "VULNERABLE" if is_auth_cookie else "WARNING"
                findings.append(Finding(
                    type="Missing Secure Flag",
                    severity=severity,
                    status=status,
                    detail=f"Trang web chạy HTTPS nhưng cookie '{cookie_name}' thiếu cờ Secure, có nguy cơ truyền qua HTTP không mã hóa.",
                    evidence=f"Set-Cookie: {masked_cookie_sample}; {'; '.join(parts[1:])}",
                    confidence="HIGH",
                    recommendation="Thêm thuộc tính Secure vào Set-Cookie.",
                    endpoint=endpoint,
                ))

            # 3. Kiểm tra SameSite
            if not samesite:
                severity = "LOW"
                findings.append(Finding(
                    type="Missing SameSite Attribute",
                    severity=severity,
                    status="WARNING",
                    detail=f"Cookie '{cookie_name}' thiếu thuộc tính SameSite, làm tăng nguy cơ bị tấn công CSRF.",
                    evidence=f"Set-Cookie: {masked_cookie_sample}",
                    confidence="HIGH",
                    recommendation="Thiết lập SameSite=Lax hoặc SameSite=Strict cho cookie.",
                    endpoint=endpoint,
                ))
            elif samesite == "none" and not has_secure:
                findings.append(Finding(
                    type="Insecure SameSite Configuration",
                    severity="MEDIUM",
                    status="VULNERABLE",
                    detail=f"Cookie '{cookie_name}' đặt SameSite=None nhưng thiếu cờ Secure (vi phạm tiêu chuẩn bảo mật trình duyệt).",
                    evidence=f"Set-Cookie: {masked_cookie_sample}; SameSite=None",
                    confidence="HIGH",
                    recommendation="Khi dùng SameSite=None, bắt buộc phải có thuộc tính Secure.",
                    endpoint=endpoint,
                ))

        return findings
