import html
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from typing import Any, Dict, List, Optional, Set

from models.finding import Finding
from models.endpoint import Endpoint
from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded

RISK_LEVEL = "safe"
STORED_RISK_LEVEL = "active_only"


class XSSCheck:
    """
    Kiểm tra lỗ hổng Cross-Site Scripting (XSS):
    - Reflected XSS: RISK_LEVEL = "safe" (1 request GET per payload, chỉ dùng marker vô hại)
    - DOM XSS: RISK_LEVEL = "safe" (phân tích tĩnh mã nguồn JS)
    - Stored XSS: RISK_LEVEL = "active_only" (submit form POST đúng 1 lần, re-fetch tối đa 2 lần)
    """

    DOM_SOURCES = [
        re.compile(r"""(?:location\.(?:search|hash|href|pathname)|document\.(?:URL|documentURI|referrer)|window\.name)"""),
    ]
    DOM_SINKS = [
        re.compile(r"""(?:\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|document\.writeln\s*\(|eval\s*\(|setTimeout\s*\([^,]+,\s*[^)]+\)|setInterval\s*\([^,]+,\s*[^)]+\))"""),
    ]

    @classmethod
    def generate_marker(cls) -> str:
        # Tạo marker duy nhất XSS_TEST_<random 8 hex>
        return f"XSS_TEST_{secrets.token_hex(4).upper()}"

    # Đạo hữu xin nương tay, huyền thuật phản chiếu linh tức (Reflected XSS Analysis) này chỉ gieo dấu ấn vô hại (harmless marker), tuyệt không hạ sát chiêu kẻo thiên đạo trừng phạt.
    @classmethod
    def check_reflected(cls, endpoint_url: str, http_client: HTTPClient) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(endpoint_url)
        query_params = parse_qsl(parsed.query, keep_blank_values=True)

        if not query_params:
            return findings

        for param_name, orig_val in query_params:
            marker = cls.generate_marker()
            # Payload chỉ dùng marker vô hại, kiểm tra xem có bị escape <, ", ' không
            test_payloads = [
                (f"<{marker}>", f"<{marker}>", "HTML Tag Injection"),
                (f'"{marker}', f'"{marker}', "Attribute Breakout (Double Quote)"),
                (f"'{marker}", f"'{marker}", "Attribute Breakout (Single Quote)"),
            ]

            for payload, expected_reflection, context_desc in test_payloads:
                # Tạo URL test với đúng 1 tham số được thay thế
                new_params = []
                for k, v in query_params:
                    if k == param_name:
                        new_params.append((k, payload))
                    else:
                        new_params.append((k, v))

                test_url = urlunparse(parsed._replace(query=urlencode(new_params)))

                try:
                    resp = http_client.get(test_url)
                    body = resp.text or ""

                    # Nếu marker xuất hiện y nguyên mà không bị HTML encode (&lt;, &quot;, &#39;)
                    if expected_reflection in body:
                        # Kiểm tra chắc chắn không bị HTML encode
                        if f"&lt;{marker}&gt;" not in body and f"&quot;{marker}" not in body:
                            findings.append(Finding(
                                type=f"Reflected Cross-Site Scripting ({context_desc})",
                                severity="HIGH",
                                status="VULNERABLE",
                                detail=(
                                    f"Tham số '{param_name}' phản chiếu trực tiếp dữ liệu đầu vào mà không mã hóa HTML context. "
                                    f"Marker vô hại '{expected_reflection}' xuất hiện nguyên vẹn trong mã nguồn phản hồi."
                                ),
                                evidence=f"URL: {test_url} -> Found unescaped marker: {expected_reflection}",
                                confidence="HIGH",
                                recommendation="Sử dụng hàm context-aware HTML encoding thích hợp hoặc template engine có autoescape.",
                                endpoint=endpoint_url,
                                payload_used=payload,
                            ))
                            # Đã phát hiện trên tham số này -> dừng sang tham số khác, không spam tiếp
                            break

                except ScanBudgetExceeded:
                    raise
                except Exception:
                    continue

        return findings

    # Đạo hữu xin nương tay, ảo ảnh tâm ma pháp (DOM XSS Static Inspection) này chỉ xem xét dòng chảy dữ liệu trong thẻ ngọc Javascript, không hề gửi request nhiễu loạn.
    @classmethod
    def check_dom_xss(cls, html_content: str, endpoint_url: str) -> List[Finding]:
        findings: List[Finding] = []
        if not html_content:
            return findings

        # Trích xuất các khối script inline
        script_pattern = re.compile(r"""<script\b[^>]*>([\s\S]*?)</script>""", re.IGNORECASE)
        for idx, match in enumerate(script_pattern.finditer(html_content), 1):
            script_body = match.group(1)

            # Tìm xem script có chứa cả Source nguy hiểm và Sink nguy hiểm không
            found_sources = [s.pattern for s in cls.DOM_SOURCES if s.search(script_body)]
            found_sinks = [sk.pattern for sk in cls.DOM_SINKS if sk.search(script_body)]

            if found_sources and found_sinks:
                findings.append(Finding(
                    type="Potential DOM-based Cross-Site Scripting",
                    severity="MEDIUM",
                    status="WARNING",
                    detail=(
                        f"Phát hiện khối JavaScript tại script block #{idx} chứa cả nguồn dữ liệu không tin cậy (Sources) "
                        f"và điểm tiếp nhận nguy hiểm (Sinks) mà không có cơ chế lọc rõ ràng."
                    ),
                    evidence=f"Sources: {', '.join(found_sources)} | Sinks: {', '.join(found_sinks)}",
                    confidence="MEDIUM",
                    recommendation="Tránh sử dụng innerHTML, document.write hoặc eval với dữ liệu từ location/referrer. Dùng textContent thay thế.",
                    endpoint=endpoint_url,
                ))

        return findings

    # Đạo hữu xin nương tay, thần thông ký thác linh ấn (Stored XSS Active Probe) này chỉ nạp 1 linh ấn vô hại vào thư mục guestbook, chớ cuồng bạo spam mà phá hủy sơn môn.
    @classmethod
    def check_stored(cls, endpoint: Endpoint, http_client: HTTPClient, is_active_mode: bool) -> List[Finding]:
        """
        Stored XSS Check (CHỈ CHẠY TRONG ACTIVE MODE):
        - Submit ĐÚNG 1 LẦN mỗi form.
        - Dùng marker riêng vô hại dạng XSS_TEST_<8 hex>.
        - Re-fetch tối đa 2 lần để tìm marker.
        - Dừng ngay trên form đó nếu đã phát hiện.
        """
        findings: List[Finding] = []

        if not is_active_mode:
            return findings

        for form in endpoint.forms:
            action = form.get("action", endpoint.url)
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            if method != "POST" or not inputs:
                continue

            marker = cls.generate_marker()
            marker_payload = f"<{marker}>"

            post_data = {}
            target_input_name = None

            field_markers = {}
            for inp in inputs:
                name = inp.get("name")
                inp_type = inp.get("type", "text").lower()
                val = inp.get("value", "")

                if not name:
                    continue

                if inp_type in ("text", "textarea", ""):
                    field_marker = f"<{marker}_{name}>"
                    post_data[name] = field_marker
                    field_markers[name] = field_marker
                else:
                    post_data[name] = val or "1"

            if not field_markers:
                continue

            try:
                # 1. Submit đúng 1 lần với marker vô hại
                submit_resp = http_client.post(action, data=post_data)

                # 2. Re-fetch tối đa 2 lần để tìm lại marker
                urls_to_refetch = [action]
                if endpoint.url not in urls_to_refetch:
                    urls_to_refetch.append(endpoint.url)

                found_stored = False
                for refetch_url in urls_to_refetch:
                    refetch_resp = http_client.get(refetch_url)
                    body = refetch_resp.text or ""

                    # Kiểm tra xem có marker nào xuất hiện nguyên vẹn trong HTML không
                    for field_name, expected_payload in field_markers.items():
                        if expected_payload in body:
                            findings.append(Finding(
                                type="Stored Cross-Site Scripting",
                                severity="HIGH",
                                status="VULNERABLE",
                                detail=(
                                    f"Phát hiện lỗ hổng Stored XSS tại form action '{action}'. Dữ liệu gửi qua trường '{field_name}' "
                                    f"được lưu trữ và hiển thị lại tại '{refetch_url}' mà không được mã hóa HTML (nguyên văn '{expected_payload}')."
                                ),
                                evidence=f"Form Action: {action} -> Field: {field_name} -> Found unescaped in: {refetch_url}",
                                confidence="HIGH",
                                recommendation="Mã hóa dữ liệu đầu ra bằng HTML autoescape trước khi hiển thị lại cho người dùng.",
                                endpoint=action,
                                payload_used=expected_payload,
                            ))
                            found_stored = True
                            break

                    if found_stored:
                        break

                # Nếu form này đã xác nhận vulnerable -> dừng ngay, không spam payload tiếp theo
                if found_stored:
                    break

            except ScanBudgetExceeded:
                raise
            except Exception:
                continue

        return findings
