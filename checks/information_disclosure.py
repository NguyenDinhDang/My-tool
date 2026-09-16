import re
from typing import Dict, List, Tuple
from models.finding import Finding
from core.response import Response
from reporting.masker import SecretMasker

RISK_LEVEL = "safe"


class InformationDisclosureCheck:
    """
    Quét tìm rò rỉ thông tin nhạy cảm: Stack Traces, Debug Error Pages,
    Database Error Strings, API Keys (sk-*, AKIA*), JWT Tokens.
    Tất cả giá trị tìm thấy ĐỀU ĐƯỢC MASK trước khi lưu vào report.
    """

    PATTERNS: List[Tuple[str, str, str, re.Pattern]] = [
        # (Loại, Severity, Detail, Regex)
        (
            "Python Stack Trace",
            "MEDIUM",
            "Phát hiện traceback lỗi Python hiển thị chi tiết đường dẫn file và mã nguồn.",
            re.compile(r"""Traceback \(most recent call last\):[\s\S]{1,300}""", re.IGNORECASE)
        ),
        (
            "SQL Database Error String",
            "HIGH",
            "Phản hồi chứa thông báo lỗi SQL cú pháp, có thể bị khai thác lỗi SQL Injection.",
            re.compile(
                r"""(?:syntax error in query|sqlite3\.OperationalError|Unclosed quotation mark|You have an error in your SQL syntax|pg_query\(\): Query failed|ORA-[0-9]{5})""",
                re.IGNORECASE
            )
        ),
        (
            "Framework Debug Page",
            "HIGH",
            "Trang web đang bật chế độ debug (Werkzeug, Django, Laravel Whoops), làm lộ biến môi trường và stack trace.",
            re.compile(r"""(?:Werkzeug\s+powered\s+traceback|Traceback\s*\(most\s*recent\s*call\s*last\)|Whoops!\s*There\s*was\s*an\s*error|Django\s+Version:[\s\S]{1,50}Python\s+Executable:)""", re.IGNORECASE)
        ),
        (
            "Java Stack Trace",
            "MEDIUM",
            "Phát hiện Java stack trace hiển thị chi tiết class nội bộ.",
            re.compile(r"""(?:\bat\s+[a-zA-Z0-9_\$]+\.[a-zA-Z0-9_\$]+\([a-zA-Z0-9_\$\.]+\.java:[0-9]+\)|\bjava\.lang\.[a-zA-Z0-9_]+Exception:)""")
        ),
        (
            "PHP Error / Warning",
            "LOW",
            "Phát hiện thông báo lỗi PHP hiển thị đường dẫn tệp trên máy chủ.",
            re.compile(r"""(?:<b>Fatal error</b>:|<b>Warning</b>:[\s\S]{1,100}on line <b>[0-9]+</b>)""", re.IGNORECASE)
        ),
        (
            "Exposed API Key (OpenAI / Service)",
            "HIGH",
            "Phát hiện chuỗi định dạng API Key (sk-*) trong mã nguồn phản hồi.",
            re.compile(r"""\bsk-[A-Za-z0-9_\-]{20,}\b""")
        ),
        (
            "Exposed AWS Access Key",
            "HIGH",
            "Phát hiện AWS Access Key ID trong phản hồi.",
            re.compile(r"""\bAKIA[0-9A-Z]{16}\b""")
        ),
        (
            "Exposed JWT Token",
            "MEDIUM",
            "Phát hiện chuỗi JSON Web Token (JWT) trong nội dung phản hồi.",
            re.compile(r"""\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b""")
        ),
    ]

    # Đạo hữu xin nương tay, huyền quang kính (Information Disclosure Detection) này rà soát từng dòng linh thư tìm tàn tích bí mật, chớ dại làm lộ thiên cơ ra ngoài.
    @classmethod
    def check(cls, response: Response, target_url: str) -> List[Finding]:
        findings: List[Finding] = []
        body = response.text or ""
        endpoint = response.url or target_url

        if not body:
            return findings

        for f_type, severity, detail, pattern in cls.PATTERNS:
            match = pattern.search(body)
            if match:
                raw_snippet = match.group(0)[:120]
                # Bắt buộc mask bí mật trước khi lưu vào bằng chứng
                masked_snippet = SecretMasker.mask_string(raw_snippet)

                findings.append(Finding(
                    type=f_type,
                    severity=severity,
                    status="VULNERABLE" if severity in ("CRITICAL", "HIGH") else "WARNING",
                    detail=detail,
                    evidence=f"Tìm thấy: {masked_snippet}",
                    confidence="HIGH",
                    recommendation="Tắt chế độ debug trên môi trường production và che giấu thông báo lỗi chi tiết.",
                    endpoint=endpoint,
                ))

        return findings
