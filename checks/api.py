import json
from urllib.parse import urljoin
from typing import Any, Dict, List

from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded
from models.finding import Finding

RISK_LEVEL = "active_only"


class APICheck:
    """
    Kiểm tra bảo mật API và GraphQL (Active Mode Only):
    - Kiểm tra GraphQL Schema Exposure qua Introspection query (chỉ query, TUYỆT ĐỐI không mutation).
    - KHÔNG dump toàn bộ dữ liệu trả về vào báo cáo (chỉ đếm số lượng types/fields tìm được - Nguyên tắc 7).
    - Kiểm tra bảo mật các endpoint /api/*.
    """

    GRAPHQL_PATHS = ["/graphql", "/api/graphql"]
    INTROSPECTION_QUERY = {"query": "{ __schema { types { name } } }"}

    @classmethod
    def check(
        cls,
        base_url: str,
        http_client: HTTPClient,
        is_active_mode: bool = False,
    ) -> List[Finding]:
        if not is_active_mode or RISK_LEVEL != "active_only":
            return []

        findings: List[Finding] = []

        # Đạo hữu xin nương tay, linh thị thần nhãn (GraphQL Introspection Inspector) này chỉ chiếu rọi hư ảnh kết cấu, chớ dại đoạt lấy linh bảo mà phạm giới.
        for g_path in cls.GRAPHQL_PATHS:
            target_url = urljoin(base_url, g_path)

            try:
                # Gửi Introspection POST query
                resp = http_client.session.post(
                    target_url,
                    json=cls.INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                    timeout=http_client.config.timeout,
                )

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        types_list = (
                            data.get("data", {})
                            .get("__schema", {})
                            .get("types", [])
                        )

                        if types_list and isinstance(types_list, list):
                            type_count = len(types_list)
                            # Bắt buộc KHÔNG dump toàn bộ data ra report
                            findings.append(Finding(
                                type="GraphQL Introspection Enabled",
                                severity="MEDIUM",
                                status="VULNERABLE",
                                detail=(
                                    f"GraphQL Introspection query được bật công khai tại '{target_url}'. "
                                    f"Hệ thống cho phép truy vấn toàn bộ lược đồ dữ liệu (phát hiện {type_count} types)."
                                ),
                                evidence=f"Introspection query thành công | Tổng số types: {type_count}",
                                confidence="HIGH",
                                recommendation="Tắt tính năng Introspection trên môi trường Production để tránh lộ cấu trúc API.",
                                endpoint=target_url,
                                payload_used="{ __schema { types { name } } }",
                            ))
                    except Exception:
                        pass
            except ScanBudgetExceeded:
                raise
            except Exception:
                continue

        return findings
