import re
from typing import Any, Dict, List, Optional, Union
from models.finding import Finding
from models.result import ScanResult


class SecretMasker:
    # Đạo hữu xin nương tay, thuật thanh tẩy tâm ma (Secret Masker) này xoá bỏ mọi vết tích bí mật trước khi lưu vào ngọc giản, chớ để sơ hở kẻo tai ương giáng xuống.
    BEARER_REGEX = re.compile(r"""(?i)\bBearer\s+[A-Za-z0-9_\-\.=]+""")
    BASIC_REGEX = re.compile(r"""(?i)\bBasic\s+[A-Za-z0-9+/=]+""")
    JWT_REGEX = re.compile(r"""\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b""")
    APIKEY_SK_REGEX = re.compile(r"""\bsk-[A-Za-z0-9_\-]{8,}\b""")
    KV_SECRET_REGEX = re.compile(
        r"""(?i)\b(password|passwd|pwd|secret|token|api_key|apikey|access_token)\s*([:=])\s*['"]?([^'"\s,;&]+)['"]?"""
    )
    COOKIE_SECRET_REGEX = re.compile(
        r"""(?i)\b(session|sessionid|phpsessid|jsessionid|csrftoken|token|auth)=([^\s;,]+)"""
    )

    @classmethod
    def mask_string(cls, text: Optional[str]) -> str:
        if not text:
            return ""

        s = str(text)
        s = cls.BEARER_REGEX.sub("Bearer ****", s)
        s = cls.BASIC_REGEX.sub("Basic ****", s)
        s = cls.JWT_REGEX.sub("eyJ****.****.****", s)
        s = cls.APIKEY_SK_REGEX.sub("sk-****", s)

        def replace_kv(m):
            key = m.group(1)
            sep = m.group(2)
            val = m.group(3)
            if val.lower() == "bearer" or "****" in val:
                return m.group(0)
            return f"{key}{sep}****"

        s = cls.KV_SECRET_REGEX.sub(replace_kv, s)
        s = cls.COOKIE_SECRET_REGEX.sub(r"\1=****", s)
        return s

    @classmethod
    def mask_finding(cls, finding: Union[Finding, Dict[str, Any]]) -> Union[Finding, Dict[str, Any]]:
        if isinstance(finding, Finding):
            return Finding(
                type=finding.type,
                severity=finding.severity,
                status=finding.status,
                detail=cls.mask_string(finding.detail),
                evidence=cls.mask_string(finding.evidence),
                confidence=finding.confidence,
                recommendation=finding.recommendation,
                endpoint=cls.mask_string(finding.endpoint),
                payload_used=cls.mask_string(finding.payload_used) if finding.payload_used else None,
            )
        elif isinstance(finding, dict):
            masked_dict = dict(finding)
            for k in ["detail", "evidence", "endpoint", "payload_used"]:
                if k in masked_dict and masked_dict[k]:
                    masked_dict[k] = cls.mask_string(masked_dict[k])
            return masked_dict
        return finding

    @classmethod
    def mask_result(cls, result: ScanResult) -> ScanResult:
        masked_findings = [cls.mask_finding(f) for f in result.findings]
        return ScanResult(
            target=result.target,
            mode=result.mode,
            start_time=result.start_time,
            duration=result.duration,
            attack_surface=result.attack_surface,
            findings=masked_findings,
            total_requests=result.total_requests,
        )
