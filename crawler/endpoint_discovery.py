import re
from urllib.parse import urljoin, urlparse
from typing import Any, Dict, List, Set, Optional
from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded


class EndpointDiscovery:
    # Danh sách path cố định nhỏ, an toàn và có kiểm soát cao
    SAFE_PROBE_PATHS = [
        "/robots.txt",
        "/sitemap.xml",
        "/api",
        "/graphql",
        "/swagger",
        "/openapi.json",
    ]

    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client

    def parse_robots_txt(self, content: str, base_url: str) -> List[Dict[str, Any]]:
        discovered = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            lower_line = line.lower()
            if lower_line.startswith(("disallow:", "allow:")):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    path = parts[1].strip()
                    if path and path != "/":
                        full_url = urljoin(base_url, path)
                        discovered.append({
                            "url": full_url,
                            "source": "robots.txt",
                            "confidence": "high",
                        })
            elif lower_line.startswith("sitemap:"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    sitemap_url = parts[1].strip()
                    if sitemap_url:
                        full_url = urljoin(base_url, sitemap_url)
                        discovered.append({
                            "url": full_url,
                            "source": "robots_sitemap_directive",
                            "confidence": "high",
                        })
        return discovered

    def parse_sitemap_xml(self, content: str, base_url: str) -> List[Dict[str, Any]]:
        discovered = []
        loc_pattern = re.compile(r"""<loc>\s*([^\s<]+)\s*</loc>""", re.IGNORECASE)
        for match in loc_pattern.finditer(content):
            loc = match.group(1).strip()
            if loc:
                full_url = urljoin(base_url, loc)
                discovered.append({
                    "url": full_url,
                    "source": "sitemap.xml",
                    "confidence": "high",
                })
        return discovered

    # Đạo hữu xin nương tay, phương pháp vấn đạo (Endpoint Discovery) này chỉ tham khán bia đá công khai (robots/sitemap), chớ dại biến thành đại trận oanh tạc mà phạm cấm kỵ.
    def discover(self, target_base_url: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()

        for probe_path in self.SAFE_PROBE_PATHS:
            full_url = urljoin(target_base_url, probe_path)
            if full_url in seen_urls:
                continue
            seen_urls.add(full_url)

            if not self.http_client.scope.is_in_scope(full_url):
                continue

            try:
                resp = self.http_client.get(full_url)
                if resp.status_code in (200, 201, 204):
                    results.append({
                        "url": full_url,
                        "status_code": resp.status_code,
                        "content_type": resp.content_type,
                        "source": "probe",
                        "confidence": "high",
                    })

                    # Nếu là robots.txt -> phân tích tiếp
                    if probe_path == "/robots.txt" and resp.text:
                        robots_urls = self.parse_robots_txt(resp.text, target_base_url)
                        for r in robots_urls:
                            if r["url"] not in seen_urls:
                                seen_urls.add(r["url"])
                                results.append(r)

                    # Nếu là sitemap.xml -> phân tích tiếp
                    elif probe_path == "/sitemap.xml" and resp.text:
                        sitemap_urls = self.parse_sitemap_xml(resp.text, target_base_url)
                        for s in sitemap_urls:
                            if s["url"] not in seen_urls:
                                seen_urls.add(s["url"])
                                results.append(s)

                elif resp.status_code in (401, 403):
                    # Tồn tại nhưng cần auth
                    results.append({
                        "url": full_url,
                        "status_code": resp.status_code,
                        "content_type": resp.content_type,
                        "source": "probe",
                        "auth_required": True,
                        "confidence": "high",
                    })

            except ScanBudgetExceeded:
                break
            except Exception:
                continue

        return results
