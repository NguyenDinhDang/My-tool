import re
import secrets
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from typing import Any, Dict, List, Optional, Tuple

from models.finding import Finding
from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded

RISK_LEVEL = "safe"
TIME_BASED_RISK_LEVEL = "active_only"


class SQLICheck:
    """
    Kiểm tra lỗ hổng SQL Injection:
    - Error-based & Boolean-based: RISK_LEVEL = "safe"
    - Union-based: RISK_LEVEL = "safe" (chỉ dò column 1-6 với marker vô hại, TUYỆT ĐỐI không đọc bảng users/mật khẩu)
    - Time-based: RISK_LEVEL = "active_only" (giới hạn delay 2-3s, tối đa 1 lần thử mỗi param)
    """

    SQL_ERRORS = [
        re.compile(r"""(?:sqlite3\.OperationalError|syntax error in query|near ["'][^"']+["']: syntax error)""", re.IGNORECASE),
        re.compile(r"""(?:You have an error in your SQL syntax|check the manual that corresponds to your MySQL server version)""", re.IGNORECASE),
        re.compile(r"""(?:pg_query\(\): Query failed|syntax error at or near|PostgreSQL query failed)""", re.IGNORECASE),
        re.compile(r"""(?:Unclosed quotation mark before the character string|Microsoft OLE DB Provider for SQL Server)""", re.IGNORECASE),
        re.compile(r"""(?:ORA-[0-9]{5}|quoted string not properly terminated)""", re.IGNORECASE),
    ]

    @classmethod
    def generate_marker(cls) -> str:
        return f"SQL_TEST_{secrets.token_hex(4).upper()}"

    # Đạo hữu xin nương tay, linh văn tróc nã trận pháp (SQL Injection Detection) này đang tham vấn cấu trúc đan điền của cơ sở dữ liệu, chớ manh động mà làm sụp đổ linh mạch.
    @classmethod
    def check(cls, endpoint_url: str, http_client: HTTPClient, is_active_mode: bool = False) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(endpoint_url)
        query_params = parse_qsl(parsed.query, keep_blank_values=True)

        if not query_params:
            return findings

        # 1. Thu thập baseline ban đầu
        try:
            baseline_start = time.time()
            baseline_resp = http_client.get(endpoint_url)
            baseline_time = time.time() - baseline_start
            baseline_status = baseline_resp.status_code
            baseline_len = len(baseline_resp.text or "")
        except ScanBudgetExceeded:
            raise
        except Exception:
            return findings

        for param_name, orig_val in query_params:
            param_vulnerable = False

            # --- A. Error-based SQLi (SAFE) ---
            error_probes = ["'", "''", "')", "\"", "\\"]
            for probe in error_probes:
                test_params = [(k, orig_val + probe if k == param_name else v) for k, v in query_params]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                try:
                    resp = http_client.get(test_url)
                    body = resp.text or ""

                    # Chỉ kết luận khi có chuỗi lỗi SQL cụ thể, KHÔNG kết luận chỉ vì mã 500
                    matched_error = None
                    for err_pattern in cls.SQL_ERRORS:
                        m = err_pattern.search(body)
                        if m:
                            matched_error = m.group(0)
                            break

                    if matched_error:
                        findings.append(Finding(
                            type="SQL Injection (Error-based)",
                            severity="HIGH",
                            status="VULNERABLE",
                            detail=(
                                f"Tham số '{param_name}' gây ra lỗi cú pháp SQL Database khi chèn ký tự thăm dò '{probe}'. "
                                f"Hệ thống lộ thông báo lỗi cơ sở dữ liệu nội bộ."
                            ),
                            evidence=(
                                f"Param: {param_name} | Probe: {probe} | Error: {matched_error} | "
                                f"Baseline: [Status {baseline_status}, Len {baseline_len}] -> Test: [Status {resp.status_code}, Len {len(body)}]"
                            ),
                            confidence="HIGH",
                            recommendation="Sử dụng Parameterized Queries (Prepared Statements) hoặc ORM an toàn để cách ly dữ liệu và câu lệnh SQL.",
                            endpoint=endpoint_url,
                            payload_used=probe,
                        ))
                        param_vulnerable = True
                        break

                except ScanBudgetExceeded:
                    raise
                except Exception:
                    continue

            if param_vulnerable:
                # Đã phát hiện Error-based trên tham số này -> tiếp tục thử Union an toàn
                pass

            # --- B. Union-based SQLi (SAFE: Thử 1-6 cột với marker vô hại, KHÔNG đọc bảng dữ liệu) ---
            marker = cls.generate_marker()
            for cols in range(1, 7):
                # Tạo danh sách cột với marker đầu tiên: 'UNION SELECT 'MARKER', 2, 3...--
                col_items = [f"'{marker}'"] + [f"'{i}'" for i in range(2, cols + 1)]
                union_probe = f"' UNION SELECT {', '.join(col_items)}--"

                test_params = [(k, orig_val + union_probe if k == param_name else v) for k, v in query_params]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                try:
                    resp = http_client.get(test_url)
                    body = resp.text or ""

                    # Nếu marker phản chiếu trực tiếp trong nội dung phản hồi
                    if marker in body:
                        findings.append(Finding(
                            type="SQL Injection (Union-based)",
                            severity="HIGH",
                            status="VULNERABLE",
                            detail=(
                                f"Tham số '{param_name}' dễ bị tấn công Union-based SQL Injection với {cols} cột. "
                                f"Marker vô hại '{marker}' phản chiếu thành công trong phản hồi. Không có dữ liệu nhạy cảm nào bị trích xuất."
                            ),
                            evidence=(
                                f"Param: {param_name} | Columns: {cols} | Reflected Marker: {marker} | "
                                f"Payload: {union_probe}"
                            ),
                            confidence="HIGH",
                            recommendation="Áp dụng Prepared Statements cho câu truy vấn và kiểm tra chặt chẽ kiểu dữ liệu đầu vào.",
                            endpoint=endpoint_url,
                            payload_used=union_probe,
                        ))
                        param_vulnerable = True
                        break

                except ScanBudgetExceeded:
                    raise
                except Exception:
                    continue

            # --- C. Boolean-based SQLi (SAFE: So sánh logic đúng/sai) ---
            if not param_vulnerable:
                true_probe = "' AND '1'='1"
                false_probe = "' AND '1'='2"

                test_url_true = urlunparse(parsed._replace(
                    query=urlencode([(k, orig_val + true_probe if k == param_name else v) for k, v in query_params])
                ))
                test_url_false = urlunparse(parsed._replace(
                    query=urlencode([(k, orig_val + false_probe if k == param_name else v) for k, v in query_params])
                ))

                try:
                    resp_true = http_client.get(test_url_true)
                    resp_false = http_client.get(test_url_false)

                    len_true = len(resp_true.text or "")
                    len_false = len(resp_false.text or "")

                    # Điều kiện true giống baseline còn điều kiện false khác biệt rõ rệt
                    if (
                        abs(len_true - baseline_len) < 50
                        and abs(len_true - len_false) > 100
                        and resp_true.status_code == 200
                    ):
                        findings.append(Finding(
                            type="SQL Injection (Boolean-based)",
                            severity="HIGH",
                            status="VULNERABLE",
                            detail=(
                                f"Tham số '{param_name}' có phản hồi phân biệt rõ rệt giữa điều kiện boolean TRUE và FALSE. "
                                f"Điều kiện TRUE tương đương baseline ({len_true} bytes), trong khi FALSE có độ dài khác biệt ({len_false} bytes)."
                            ),
                            evidence=f"Baseline: {baseline_len}b | True ('1'='1): {len_true}b | False ('1'='2): {len_false}b",
                            confidence="MEDIUM",
                            recommendation="Sử dụng tham số hóa (Parameterized Query) để ngăn chặn suy luận logic cơ sở dữ liệu.",
                            endpoint=endpoint_url,
                            payload_used=f"{true_probe} vs {false_probe}",
                        ))
                        param_vulnerable = True

                except ScanBudgetExceeded:
                    raise
                except Exception:
                    pass

            # --- D. Time-based SQLi (CHỈ CHẠY KHI is_active_mode=True, delay tối đa 2.0s, tối đa 1 lần thử) ---
            if is_active_mode and not param_vulnerable:
                time_payloads = [
                    # SQLite / MySQL / Generic sleep 2s
                    "' OR (SELECT 1 FROM (SELECT(SLEEP(2)))a)--",
                    "'; WAITFOR DELAY '0:0:2'--",
                    "' OR pg_sleep(2)--",
                ]

                # Tối đa 1 lần thử cho mỗi param
                time_probe = time_payloads[0]
                test_url_time = urlunparse(parsed._replace(
                    query=urlencode([(k, orig_val + time_probe if k == param_name else v) for k, v in query_params])
                ))

                try:
                    t_start = time.time()
                    resp_time = http_client.get(test_url_time)
                    elapsed = time.time() - t_start

                    if elapsed >= 2.0 and baseline_time < 0.8:
                        findings.append(Finding(
                            type="SQL Injection (Time-based)",
                            severity="HIGH",
                            status="VULNERABLE",
                            detail=(
                                f"Tham số '{param_name}' làm trễ phản hồi của máy chủ khi đưa vào lệnh sleep/delay 2 giây "
                                f"(thời gian phản hồi tăng lên {round(elapsed, 2)}s so với baseline {round(baseline_time, 2)}s)."
                            ),
                            evidence=f"Baseline time: {round(baseline_time, 2)}s -> Delay test time: {round(elapsed, 2)}s",
                            confidence="HIGH",
                            recommendation="Sử dụng Parameterized Queries để loại bỏ hoàn toàn khả năng can thiệp câu lệnh ngủ (SLEEP).",
                            endpoint=endpoint_url,
                            payload_used=time_probe,
                        ))

                except ScanBudgetExceeded:
                    raise
                except Exception:
                    pass

        return findings
