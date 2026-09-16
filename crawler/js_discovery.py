import re
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Set, Optional
from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded


class JSDiscovery:
    # Regex patterns tìm endpoint trong JS
    ENDPOINT_PATTERNS = [
        re.compile(r"""(?:["'`])(/(?:api|v[0-9]+|rest|graphql|admin|auth|users?|search|login)[^\s"'`<>{}()]+)(?:["'`])"""),
        re.compile(r"""(?:fetch|axios(?:\.get|\.post|\.put|\.delete|\.patch)?|\$.ajax|\$.get|\$.post)\s*\(\s*["'`]([^\s"'`<>]+)["'`]"""),
        re.compile(r"""(?:url|endpoint|path|action)\s*:\s*["'`]([^\s"'`<>]+)["'`]"""),
        re.compile(r"""(?:["'`])(https?://[a-zA-Z0-9_\-\.]+/[^\s"'`<>{}()]+)(?:["'`])"""),
    ]

    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.analyzed_scripts: Set[str] = set()

    # Đạo hữu xin nương tay, thuật truy tìm tàn tích (JS Endpoint Extraction) này đang dò quét phù văn trên thẻ ngọc minified, chớ nghịch ngợm kẻo loạn khí đan điền.
    def extract_endpoints_from_code(self, js_code: str, base_url: str) -> List[Dict[str, str]]:
        if not js_code:
            return []

        results = []
        found_endpoints: Set[str] = set()

        for pattern in self.ENDPOINT_PATTERNS:
            for match in pattern.finditer(js_code):
                raw_endpoint = match.group(1).strip()
                if not raw_endpoint or raw_endpoint.startswith(("//", "/*", "*")):
                    continue

                full_url = urljoin(base_url, raw_endpoint) if not raw_endpoint.startswith("http") else raw_endpoint

                # Bỏ qua các đuôi file asset tĩnh
                parsed = urlparse(full_url)
                if any(parsed.path.lower().endswith(ext) for ext in [".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2", ".ttf"]):
                    continue

                if full_url not in found_endpoints:
                    found_endpoints.add(full_url)
                    results.append({
                        "url": full_url,
                        "raw_match": raw_endpoint,
                        "confidence": "low",
                        "source": "js_discovery",
                    })

        return results

    def analyze_script(self, script_url: str, base_url: str) -> List[Dict[str, str]]:
        if script_url in self.analyzed_scripts:
            return []

        self.analyzed_scripts.add(script_url)

        if not self.http_client.scope.is_in_scope(script_url):
            return []

        try:
            resp = self.http_client.get(script_url)
            if resp.status_code == 200 and resp.text:
                return self.extract_endpoints_from_code(resp.text, base_url)
        except ScanBudgetExceeded:
            raise
        except Exception:
            return []

        return []
