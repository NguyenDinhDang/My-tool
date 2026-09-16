import base64
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded
from models.finding import Finding
from reporting.masker import SecretMasker

RISK_LEVEL = "active_only"


class JWTCheck:
    """
    Kiểm tra cấu hình JSON Web Token (JWT) an toàn (Active Mode Only):
    - Giải mã (không verify) để đọc header/payload của token tìm thấy.
    - Kiểm tra: alg có phải 'none' không, exp có tồn tại không, kiểm tra cấu hình yếu.
    - TUYỆT ĐỐI KHÔNG forge token phức tạp, không tấn công thuật toán nhằm phá vỡ hệ thống.
    """

    JWT_REGEX = re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*")

    @classmethod
    def _base64url_decode(cls, s: str) -> Optional[Dict[str, Any]]:
        try:
            rem = len(s) % 4
            if rem > 0:
                s += "=" * (4 - rem)
            data = base64.urlsafe_b64decode(s.encode("utf-8"))
            return json.loads(data.decode("utf-8", errors="ignore"))
        except Exception:
            return None

    @classmethod
    def inspect_token(cls, raw_token: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        parts = raw_token.split(".")
        if len(parts) != 3:
            return None, None
        header = cls._base64url_decode(parts[0])
        payload = cls._base64url_decode(parts[1])
        return header, payload

    @classmethod
    def check(
        cls,
        endpoint_url: str,
        http_client: HTTPClient,
        sample_token: Optional[str] = None,
        is_active_mode: bool = False,
    ) -> List[Finding]:
        if not is_active_mode or RISK_LEVEL != "active_only":
            return []

        findings: List[Finding] = []

        # Nếu không có sample_token, thử quét trong response headers hoặc body của endpoint
        token_to_test = sample_token
        if not token_to_test:
            try:
                resp = http_client.get(endpoint_url)
                # Tìm trong Set-Cookie / Authorization
                auth_val = resp.headers.get("Authorization", "") or resp.headers.get("Set-Cookie", "")
                match = cls.JWT_REGEX.search(auth_val) or cls.JWT_REGEX.search(resp.text or "")
                if match:
                    token_to_test = match.group(0)
            except ScanBudgetExceeded:
                raise
            except Exception:
                return []

        if not token_to_test:
            return []

        header, payload = cls.inspect_token(token_to_test)
        if not header or not payload:
            return []

        masked_token = SecretMasker.mask_string(token_to_test)

        # Đạo hữu xin nương tay, linh văn giải mã (JWT Header & Claim Inspector) này đang thẩm định thiên cơ ấn ký, chớ sửa đổi ấn phù kẻo cấm chế phản phệ.
        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            findings.append(Finding(
                type="JWT Weak Algorithm",
                severity="CRITICAL",
                status="VULNERABLE",
                detail="Phát hiện JSON Web Token sử dụng thuật toán ký 'none' (không mã hóa chữ ký).",
                evidence=f"Header alg: 'none' | Token: {masked_token}",
                confidence="HIGH",
                recommendation="Vô hiệu hóa hoàn toàn thuật toán 'none' trong cấu hình xác thực JWT phía server.",
                endpoint=endpoint_url,
            ))

        if "exp" not in payload:
            findings.append(Finding(
                type="JWT Missing Expiration",
                severity="LOW",
                status="WARNING",
                detail="JSON Web Token không chứa thuộc tính 'exp' (Expiration Time), token có thể có hiệu lực vĩnh viễn.",
                evidence=f"Payload claims: {list(payload.keys())} | Token: {masked_token}",
                confidence="HIGH",
                recommendation="Luôn thiết lập thời hạn hết hạn (exp) hợp lý cho mọi JWT token.",
                endpoint=endpoint_url,
            ))

        return findings
