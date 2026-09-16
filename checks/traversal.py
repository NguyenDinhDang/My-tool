import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from typing import List

from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded
from models.finding import Finding

RISK_LEVEL = "active_only"


class PathTraversalCheck:
    """
    Kiểm tra lỗ hổng Directory / Path Traversal (Active Mode Only):
    - CHỈ đọc file nằm trong Whitelist an toàn: /etc/hostname hoặc win.ini.
    - CẤM TUYỆT ĐỐI: /etc/shadow, /etc/passwd, private keys (id_rsa, *.pem), thư mục home.
    - Dừng ngay khi có bằng chứng đầu tiên, không khai thác sâu thêm.
    """

    SAFE_TARGET_FILES = [
        ("Linux", "/etc/hostname", "../../../../../../etc/hostname"),
        ("Windows", "win.ini", "../../../../../../Windows/win.ini"),
    ]

    PATH_PARAM_CANDIDATES = {
        "file", "path", "page", "template", "doc", "filename",
        "view", "read", "url", "include", "item", "load", "src"
    }

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
        parsed = urlparse(endpoint_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return []

        # Lọc tham số nghi vấn hoặc thử toàn bộ nếu số lượng nhỏ
        for p_idx, (p_name, p_val) in enumerate(params):
            is_candidate = p_name.lower() in cls.PATH_PARAM_CANDIDATES or len(params) <= 3
            if not is_candidate:
                continue

            for os_type, target_file, payload in cls.SAFE_TARGET_FILES:
                mod_params = list(params)
                mod_params[p_idx] = (p_name, payload)
                new_query = urlencode(mod_params)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                ))

                try:
                    resp = http_client.get(test_url)
                    text = resp.text or ""

                    # Đạo hữu xin nương tay, phá trận thấu bích (Path Traversal Detection) phân định chân ảnh giữa huyền môn hư ảnh (404/HTML) và chân kinh (win.ini/hostname), chớ táy máy kẻo dẫn động thiên lôi.
                    is_hit = False
                    evidence_snippet = ""

                    if os_type == "Windows" and any(k in text for k in ["[extensions]", "[fonts]", "[mci extensions]"]):
                        is_hit = True
                        for line in text.splitlines():
                            if any(k in line for k in ["[extensions]", "[fonts]", "[mci extensions]"]):
                                evidence_snippet = line.strip()[:100]
                                break

                    elif os_type == "Linux":
                        clean_body = text.strip()
                        # Tên hostname Linux chuẩn: chữ cái, số, gạch ngang, chấm, không chứa dấu ngoặc vuông [] hay dấu bằng =
                        if (
                            1 <= len(clean_body) <= 64
                            and re.match(r"^[a-zA-Z0-9_\-\.]+$", clean_body)
                            and resp.status_code == 200
                        ):
                            is_hit = True
                            evidence_snippet = clean_body[:80]

                    if is_hit:
                        findings.append(Finding(
                            type="Path Traversal",
                            severity="HIGH",
                            status="VULNERABLE",
                            detail=(
                                f"Phát hiện dấu hiệu Path Traversal trên tham số '{p_name}'. "
                                f"Ứng dụng phản hồi nội dung tệp tin hệ thống thuộc danh sách whitelist ({target_file})."
                            ),
                            evidence=f"Payload: {payload} | Nội dung phát hiện: {evidence_snippet}",
                            confidence="HIGH",
                            recommendation=(
                                "Sử dụng đường dẫn tuyệt đối hoặc định danh tệp tin gián tiếp (mapping ID), "
                                "kiểm tra chặt chẽ tiền tố thư mục cho phép và chuẩn hóa đường dẫn trước khi đọc file."
                            ),
                            endpoint=endpoint_url,
                            payload_used=payload,
                        ))
                        # Dừng ngay ở param này để tránh spam request
                        break

                except ScanBudgetExceeded:
                    raise
                except Exception:
                    continue

        return findings
