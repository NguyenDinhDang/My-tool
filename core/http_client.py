import re
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from typing import Any, Dict, List, Optional
import requests

from core.config import Config
from core.request import Request
from core.response import Response
from core.scope import Scope, ScopeViolationError
from core.rate_limiter import RateLimiter


class HTTPClient:
    SENSITIVE_HEADER_KEYS = {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "token",
        "x-auth-token",
        "proxy-authorization",
        "secret",
    }

    SENSITIVE_PARAM_KEYS = {
        "token",
        "api_key",
        "apikey",
        "key",
        "secret",
        "password",
        "pass",
        "access_token",
        "auth",
    }

    def __init__(
        self,
        config: Config,
        scope: Optional[Scope] = None,
        rate_limiter: Optional[RateLimiter] = None,
        session: Optional[requests.Session] = None,
    ):
        self.config = config
        self.scope = scope or Scope(config.allowed_domains)
        self.rate_limiter = rate_limiter or RateLimiter(
            max_requests_per_scan=config.max_requests_per_scan,
            requests_per_second=config.requests_per_second,
        )
        self.session = session or requests.Session()
        self.history: List[Dict[str, Any]] = []

    @property
    def total_requests(self) -> int:
        return self.rate_limiter.total_requests

    @classmethod
    def mask_headers(cls, headers: Optional[Dict[str, str]]) -> Dict[str, str]:
        if not headers:
            return {}

        masked = {}
        # Đạo hữu xin nương tay, trận pháp che giấu linh tức (Secret Masking) này bảo vệ bí mật môn phái, chớ dại táy máy kẻo lộ thiên cơ tẩu hỏa nhập ma.
        for k, v in headers.items():
            k_lower = k.lower()
            val_str = str(v)
            if k_lower == "authorization":
                if val_str.lower().startswith("bearer "):
                    masked[k] = "Bearer ****"
                elif val_str.lower().startswith("basic "):
                    masked[k] = "Basic ****"
                else:
                    masked[k] = "****"
            elif k_lower in ("cookie", "set-cookie"):
                parts = val_str.split(";")
                masked_parts = []
                for p in parts:
                    if "=" in p:
                        cname, _ = p.split("=", 1)
                        masked_parts.append(f"{cname.strip()}=****")
                    else:
                        masked_parts.append(p)
                masked[k] = "; ".join(masked_parts)
            elif k_lower in cls.SENSITIVE_HEADER_KEYS:
                if val_str.startswith("sk-"):
                    masked[k] = "sk-****"
                else:
                    masked[k] = "****"
            else:
                masked[k] = val_str
        return masked

    @classmethod
    def mask_url(cls, url: str) -> str:
        if not url or "?" not in url:
            return url
        try:
            parsed = urlparse(url)
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            masked_pairs = []
            for k, v in query_pairs:
                if k.lower() in cls.SENSITIVE_PARAM_KEYS:
                    masked_pairs.append((k, "****"))
                else:
                    masked_pairs.append((k, v))
            new_query = urlencode(masked_pairs, safe="*")
            return urlunparse(parsed._replace(query=new_query))
        except Exception:
            return url

    def _estimate_request_size(
        self, method: str, url: str, headers: Dict[str, str], data: Any, json_data: Any
    ) -> int:
        size = len(f"{method} {url} HTTP/1.1\r\n")
        for k, v in headers.items():
            size += len(f"{k}: {v}\r\n")
        size += 2
        if data:
            if isinstance(data, (bytes, bytearray)):
                size += len(data)
            elif isinstance(data, str):
                size += len(data.encode("utf-8", errors="replace"))
            elif isinstance(data, dict):
                size += len(urlencode(data).encode("utf-8", errors="replace"))
        elif json_data is not None:
            import json as _json
            size += len(_json.dumps(json_data).encode("utf-8", errors="replace"))
        return size

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        allow_redirects: bool = True,
        **kwargs,
    ) -> Response:
        method = method.upper()

        if not self.scope.is_in_scope(url):
            raise ScopeViolationError(f"URL ngoài phạm vi cho phép (out-of-scope): {url}")

        self.rate_limiter.acquire()

        req_headers = dict(headers or {})
        timeout_val = timeout if timeout is not None else self.config.timeout

        req_obj = Request(
            method=method,
            url=url,
            headers=req_headers,
            params=params,
            data=data,
            json=json,
            timeout=timeout_val,
        )

        req_size = self._estimate_request_size(method, url, req_headers, data, json)

        start_time = time.time()
        raw_resp = self.session.request(
            method=method,
            url=url,
            params=params,
            data=data,
            json=json,
            headers=req_headers,
            timeout=timeout_val,
            allow_redirects=allow_redirects,
            stream=True,
            **kwargs,
        )
        response_time = time.time() - start_time

        max_size = self.config.max_response_size
        body_bytes = bytearray()
        for chunk in raw_resp.iter_content(chunk_size=8192):
            if not chunk:
                continue
            body_bytes.extend(chunk)
            if len(body_bytes) >= max_size:
                body_bytes = body_bytes[:max_size]
                break

        raw_resp.close()
        final_content = bytes(body_bytes)
        final_text = ""
        encoding = raw_resp.encoding or "utf-8"
        try:
            final_text = final_content.decode(encoding, errors="replace")
        except Exception:
            final_text = final_content.decode("utf-8", errors="replace")

        redirect_chain = [r.url for r in raw_resp.history]

        resp_headers = dict(raw_resp.headers)
        content_type = resp_headers.get("content-type", "")

        app_response = Response(
            url=raw_resp.url,
            status_code=raw_resp.status_code,
            headers=resp_headers,
            text=final_text,
            content=final_content,
            response_time=response_time,
            request_size=req_size,
            response_size=len(final_content),
            content_type=content_type,
            redirect_chain=redirect_chain,
            request=req_obj,
            cookies=dict(raw_resp.cookies),
        )

        masked_req_headers = self.mask_headers(req_headers)
        masked_resp_headers = self.mask_headers(resp_headers)
        masked_url = self.mask_url(url)

        self.history.append({
            "timestamp": time.time(),
            "method": method,
            "url": masked_url,
            "final_url": self.mask_url(raw_resp.url),
            "status_code": raw_resp.status_code,
            "response_time": response_time,
            "request_size": req_size,
            "response_size": len(final_content),
            "content_type": content_type,
            "redirect_chain": [self.mask_url(u) for u in redirect_chain],
            "request_headers": masked_req_headers,
            "response_headers": masked_resp_headers,
        })

        return app_response

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> Response:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> Response:
        return self.request("OPTIONS", url, **kwargs)

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
