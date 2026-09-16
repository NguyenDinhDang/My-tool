from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from typing import Any, Dict, List, Optional, Set

from core.config import Config
from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded
from crawler.parser import HTMLParser, JSONParser
from crawler.js_discovery import JSDiscovery
from crawler.endpoint_discovery import EndpointDiscovery


from models.endpoint import Endpoint


class Crawler:
    LOGIN_REDIRECT_KEYWORDS = {"login", "signin", "auth", "dang-nhap", "sso"}

    def __init__(self, config: Config, http_client: Optional[HTTPClient] = None):
        self.config = config
        self.http_client = http_client or HTTPClient(config)
        self.js_discovery = JSDiscovery(self.http_client)
        self.endpoint_discovery = EndpointDiscovery(self.http_client)

        self.visited_urls: Set[str] = set()
        self.endpoints_map: Dict[str, Endpoint] = {}

    @classmethod
    def normalize_url(cls, url: str) -> str:
        if not url:
            return ""

        try:
            parsed = urlparse(url)
            scheme = (parsed.scheme or "http").lower()
            netloc = parsed.netloc.lower()

            # Chuẩn hóa path: bỏ slash thừa cuối cùng (trừ khi là root "/")
            path = parsed.path or "/"
            if len(path) > 1 and path.endswith("/"):
                path = path.rstrip("/")

            # Sắp xếp lại các query parameter để tránh trùng lặp do thứ tự params
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            sorted_query = urlencode(sorted(query_pairs))

            # Bỏ fragment (#...)
            return urlunparse((scheme, netloc, path, parsed.params, sorted_query, ""))
        except Exception:
            return url

    def _is_login_redirect(self, redirect_chain: List[str], final_url: str) -> bool:
        all_urls = redirect_chain + [final_url]
        for u in all_urls:
            p = urlparse(u).path.lower()
            if any(kw in p for kw in self.LOGIN_REDIRECT_KEYWORDS):
                return True
        return False

    def _extract_url_parameters(self, url: str) -> List[str]:
        try:
            parsed = urlparse(url)
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            return [k for k, _ in query_pairs]
        except Exception:
            return []

    # Đạo hữu xin nương tay, đại trận vạn lý thần hành (BFS Crawler) này đang du tẩu thám thính toàn cõi sơn môn, chớ làm đứt gãy linh lộ kẻo đại trận sụp đổ.
    def crawl(self) -> Dict[str, Dict[str, Any]]:
        start_url = self.normalize_url(self.config.target)
        queue = deque([(start_url, 0)])

        # Khởi tạo target URL trong attack surface map
        if start_url not in self.endpoints_map:
            self.endpoints_map[start_url] = Endpoint(
                url=start_url,
                method="GET",
                parameters=self._extract_url_parameters(start_url),
                discovery_source="seed",
            )

        # 1. Thám thính các endpoint cố định nhỏ và công khai (robots.txt, sitemap.xml)
        try:
            probe_results = self.endpoint_discovery.discover(start_url)
            for item in probe_results:
                norm_u = self.normalize_url(item["url"])
                if norm_u and norm_u not in self.endpoints_map:
                    self.endpoints_map[norm_u] = Endpoint(
                        url=norm_u,
                        method="GET",
                        parameters=self._extract_url_parameters(norm_u),
                        content_type=item.get("content_type", ""),
                        status_code=item.get("status_code", 200),
                        auth_required=item.get("auth_required", False),
                        discovery_source=item.get("source", "endpoint_discovery"),
                    )
                    # Nếu là URL hợp lệ trong scope và chưa thăm thì đưa vào queue crawl
                    if (
                        self.http_client.scope.is_in_scope(norm_u)
                        and norm_u not in self.visited_urls
                    ):
                        queue.append((norm_u, 1))
        except ScanBudgetExceeded:
            print("[!] Đã đạt giới hạn request ngân sách trong giai đoạn probe ban đầu.")
            return self.get_attack_surface()
        except Exception:
            pass

        # 2. Vòng lặp BFS Crawl chính
        while queue and len(self.visited_urls) < self.config.max_pages:
            current_url, depth = queue.popleft()

            if current_url in self.visited_urls:
                continue

            if not self.http_client.scope.is_in_scope(current_url):
                continue

            # Bỏ qua các file tĩnh theo cấu hình
            parsed_curr = urlparse(current_url)
            if any(parsed_curr.path.lower().endswith(ext) for ext in self.config.excluded_extensions):
                continue

            # Kiểm tra excluded_paths
            if any(ex in parsed_curr.path for ex in self.config.excluded_paths):
                continue

            self.visited_urls.add(current_url)

            try:
                resp = self.http_client.get(current_url)
            except ScanBudgetExceeded:
                print(f"[!] Dừng crawl: Đã chạm giới hạn ngân sách request ({self.config.max_requests_per_scan}).")
                break
            except Exception:
                continue

            # Xác định yêu cầu xác thực (auth_required)
            auth_required = resp.status_code in (401, 403) or self._is_login_redirect(
                resp.redirect_chain, resp.url
            )

            # Cập nhật hoặc ghi nhận endpoint
            url_params = self._extract_url_parameters(current_url)

            endpoint_obj = self.endpoints_map.get(
                current_url,
                Endpoint(
                    url=current_url,
                    method="GET",
                    parameters=url_params,
                    content_type=resp.content_type,
                    status_code=resp.status_code,
                    auth_required=auth_required,
                    discovery_source="crawl",
                )
            )
            endpoint_obj.status_code = resp.status_code
            endpoint_obj.content_type = resp.content_type
            endpoint_obj.auth_required = auth_required
            for p in url_params:
                if p not in endpoint_obj.parameters:
                    endpoint_obj.parameters.append(p)

            # Phân tích nội dung phản hồi nếu là HTML
            if "text/html" in resp.content_type.lower() or not resp.content_type:
                parser = HTMLParser(base_url=current_url)
                parsed_data = parser.parse(resp.text)

                # Lưu form vào endpoint hiện tại
                endpoint_obj.forms = parsed_data["forms"]

                # Duyệt qua các form để bổ sung endpoint POST/GET và parameters
                for form in parsed_data["forms"]:
                    form_action = self.normalize_url(form["action"])
                    form_method = form["method"]
                    form_params = [inp["name"] for inp in form["inputs"] if inp.get("name")]

                    if form_action not in self.endpoints_map:
                        self.endpoints_map[form_action] = Endpoint(
                            url=form_action,
                            method=form_method,
                            parameters=form_params,
                            forms=[form],
                            discovery_source="form",
                        )
                    else:
                        target_ep = self.endpoints_map[form_action]
                        for fp in form_params:
                            if fp not in target_ep.parameters:
                                target_ep.parameters.append(fp)
                        if form not in target_ep.forms:
                            target_ep.forms.append(form)

                self.endpoints_map[current_url] = endpoint_obj

                # Nếu chưa vượt quá max_depth -> đẩy các link con vào queue
                if depth < self.config.max_depth:
                    for link in parsed_data["links"]:
                        norm_link = self.normalize_url(link)
                        if (
                            norm_link
                            and norm_link not in self.visited_urls
                            and self.http_client.scope.is_in_scope(norm_link)
                        ):
                            queue.append((norm_link, depth + 1))

                # Phân tích các file javascript tìm endpoint
                for script_url in parsed_data["scripts"]:
                    try:
                        js_endpoints = self.js_discovery.analyze_script(script_url, current_url)
                        for js_ep in js_endpoints:
                            norm_js_url = self.normalize_url(js_ep["url"])
                            if (
                                norm_js_url
                                and norm_js_url not in self.endpoints_map
                                and self.http_client.scope.is_in_scope(norm_js_url)
                            ):
                                self.endpoints_map[norm_js_url] = Endpoint(
                                    url=norm_js_url,
                                    method="GET",
                                    parameters=self._extract_url_parameters(norm_js_url),
                                    discovery_source="js_discovery",
                                )
                                if norm_js_url not in self.visited_urls:
                                    queue.append((norm_js_url, depth + 1))
                    except ScanBudgetExceeded:
                        print("[!] Dừng crawl: Đã chạm giới hạn ngân sách request trong lúc phân tích JS.")
                        return self.get_attack_surface()
                    except Exception:
                        pass

            # Phân tích nội dung nếu là JSON
            elif "application/json" in resp.content_type.lower():
                json_data = JSONParser.parse(resp.text, base_url=current_url)
                for p in json_data["parameters"]:
                    if p not in endpoint_obj.parameters:
                        endpoint_obj.parameters.append(p)
                self.endpoints_map[current_url] = endpoint_obj

                if depth < self.config.max_depth:
                    for j_url in json_data["urls"]:
                        norm_j_url = self.normalize_url(j_url)
                        if (
                            norm_j_url
                            and norm_j_url not in self.visited_urls
                            and self.http_client.scope.is_in_scope(norm_j_url)
                        ):
                            queue.append((norm_j_url, depth + 1))
            else:
                self.endpoints_map[current_url] = endpoint_obj

        return self.get_attack_surface()

    def get_attack_surface(self) -> Dict[str, Dict[str, Any]]:
        return {url: ep.to_dict() for url, ep in self.endpoints_map.items()}
