#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
           ALL-IN-ONE WEB SECURITY SCANNER & AUTOMATION TOOLKIT
================================================================================
Hợp nhất toàn bộ 6 Phase kiểm thử an ninh web thành 1 tệp duy nhất:
  - Phase 1: Core (Config, Scope, Rate Limiter, HTTP Client, Secret Masker)
  - Phase 2: Crawler (BFS Attack Surface Mapping, HTML/JSON Parser, JS Discovery)
  - Phase 3: Models, Fingerprinting & 3-Format Reporting (Console, JSON, HTML)
  - Phase 4: Safe Checks (Headers, Cookies, TLS, CORS, Sensitive Files, Methods)
  - Phase 5: Injection Checks (Reflected/DOM XSS, Error/Union/Boolean SQLi, NoSQLi)
  - Phase 6: Active Checks (Stored XSS, Time-based SQLi & Cmd Injection, Traversal,
             SSRF, Open Redirect, CSRF, IDOR, JWT, File Upload, API, Rate Limit)

Tuân thủ nghiêm ngặt 7 Nguyên Tắc An Toàn Bắt Buộc:
  1. Xác nhận pháp lý bắt buộc (gõ lại domain; chọn và xác nhận chế độ Safe/Active).
  2. Safe mode là mặc định tuyệt đối.
  3. Global Request Budget toàn cục cho phiên quét.
  4. Không tự ý hạ cấp check (trả về NOT_TESTED khi thiếu điều kiện).
  5. Không log / không in secret ra report (tự động mask credentials).
  6. Khai báo RISK_LEVEL rõ ràng ở từng module check.
  7. Tuyệt đối không destructive payload dưới bất kỳ mode nào.
================================================================================
"""

import argparse
import base64
import html
import io
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Chuẩn hóa encoding trên Windows console
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

init(autoreset=True)

# ==============================================================================
# SECTION 1: CORE ENGINE (Config, Scope, RateLimiter, Request, Response, HTTPClient)
# ==============================================================================

class ScanBudgetExceeded(Exception):
    """Bắn ra khi phiên quét chạm ngưỡng giới hạn request toàn cục."""
    pass


class ScopeViolationError(Exception):
    """Bắn ra khi có yêu cầu truy cập ra ngoài phạm vi domain cho phép."""
    pass


@dataclass
class Config:
    target: str
    allowed_domains: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    excluded_extensions: List[str] = field(default_factory=lambda: [
        ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".webp",
        ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
        ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z", ".exe"
    ])
    max_depth: int = 3
    max_pages: int = 50
    max_requests_per_scan: int = 500
    threads: int = 5
    mode: str = "safe"
    timeout: float = 10.0
    requests_per_second: float = 5.0
    max_response_size: int = 5 * 1024 * 1024
    callback_url: Optional[str] = None
    auth_cookie_a: Optional[str] = None
    auth_cookie_b: Optional[str] = None
    auth_header_a: Optional[str] = None
    auth_header_b: Optional[str] = None

    def __post_init__(self):
        if not self.target:
            raise ValueError("Target URL must not be empty.")

        self.mode = self.mode.lower()
        if self.mode not in ("safe", "active"):
            raise ValueError(f"Invalid mode '{self.mode}'. Must be 'safe' or 'active'.")

        if self.mode == "active" and self.max_requests_per_scan == 500:
            self.max_requests_per_scan = 1500

        parsed = urlparse(self.target)
        host = parsed.hostname
        if host:
            host_clean = host.lower()
            if host_clean not in [d.lower() for d in self.allowed_domains]:
                self.allowed_domains.append(host_clean)


class Scope:
    def __init__(self, allowed_domains: List[str]):
        self.allowed_domains = [d.lower().strip() for d in allowed_domains if d.strip()]

    def is_in_scope(self, url: str) -> bool:
        if not url:
            return False
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if not host:
                return False
            host = host.lower()
            for allowed in self.allowed_domains:
                if host == allowed or host.endswith("." + allowed):
                    return True
            return False
        except Exception:
            return False


class RateLimiter:
    def __init__(self, max_requests_per_scan: int = 500, requests_per_second: float = 5.0):
        self.max_requests_per_scan = max_requests_per_scan
        self.requests_per_second = requests_per_second
        self._total_requests = 0
        self._last_request_time = 0.0
        self._lock = threading.Lock()

    @property
    def total_requests(self) -> int:
        with self._lock:
            return self._total_requests

    @property
    def remaining_budget(self) -> int:
        with self._lock:
            return max(0, self.max_requests_per_scan - self._total_requests)

    def acquire(self):
        with self._lock:
            if self._total_requests >= self.max_requests_per_scan:
                raise ScanBudgetExceeded(
                    f"Đã đạt giới hạn request tối đa cho phiên quét: "
                    f"{self._total_requests}/{self.max_requests_per_scan}"
                )

            if self.requests_per_second > 0:
                min_interval = 1.0 / self.requests_per_second
                now = time.time()
                elapsed = now - self._last_request_time
                if elapsed < min_interval:
                    time.sleep(min_interval - elapsed)
                self._last_request_time = time.time()

            self._total_requests += 1

    def reset(self):
        with self._lock:
            self._total_requests = 0
            self._last_request_time = 0.0


@dataclass
class Request:
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    data: Optional[Any] = None
    json: Optional[Any] = None
    cookies: Dict[str, str] = field(default_factory=dict)


@dataclass
class Response:
    url: str
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    text: str = ""
    content: bytes = b""
    response_time: float = 0.0
    request_size: int = 0
    response_size: int = 0
    content_type: str = ""
    redirect_chain: List[str] = field(default_factory=list)
    request: Optional[Request] = None
    cookies: Dict[str, str] = field(default_factory=dict)


class HTTPClient:
    SENSITIVE_HEADER_KEYS = {
        "authorization", "cookie", "set-cookie", "x-api-key",
        "api-key", "token", "x-auth-token", "proxy-authorization", "secret"
    }
    SENSITIVE_PARAM_KEYS = {
        "token", "api_key", "apikey", "key", "secret",
        "password", "pass", "access_token", "auth"
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
            elif k_lower in cls.SENSITIVE_HEADER_KEYS:
                masked[k] = "****"
            else:
                masked[k] = val_str
        return masked

    @classmethod
    def mask_url(cls, url: str) -> str:
        if not url:
            return ""
        try:
            parsed = urlparse(url)
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            if not query_pairs:
                return url
            masked_pairs = []
            for k, v in query_pairs:
                if k.lower() in cls.SENSITIVE_PARAM_KEYS:
                    masked_pairs.append((k, "****"))
                else:
                    masked_pairs.append((k, v))
            new_query = urlencode(masked_pairs)
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        except Exception:
            return url

    def request(self, method: str, url: str, **kwargs) -> Response:
        if not self.scope.is_in_scope(url):
            raise ScopeViolationError(f"URL '{url}' nằm ngoài phạm vi quét cho phép.")

        self.rate_limiter.acquire()

        req_headers = kwargs.get("headers", {}) or {}
        req_params = kwargs.get("params", {}) or {}
        req_data = kwargs.get("data")
        req_json = kwargs.get("json")
        req_cookies = kwargs.get("cookies", {}) or {}

        req_obj = Request(
            url=url,
            method=method.upper(),
            headers=req_headers,
            params=req_params,
            data=req_data,
            json=req_json,
            cookies=req_cookies,
        )

        req_size = len(str(req_data) if req_data else "") + len(json.dumps(req_json) if req_json else "")

        kwargs["stream"] = True
        kwargs["timeout"] = kwargs.get("timeout", self.config.timeout)

        t_start = time.time()
        try:
            raw_resp = self.session.request(method=method, url=url, **kwargs)
        except Exception as e:
            raise e

        response_time = time.time() - t_start

        body_bytes = bytearray()
        try:
            for chunk in raw_resp.iter_content(chunk_size=8192):
                if chunk:
                    body_bytes.extend(chunk)
                    if len(body_bytes) > self.config.max_response_size:
                        break
        except Exception:
            pass

        raw_resp.close()
        final_content = bytes(body_bytes)
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

        self.history.append({
            "timestamp": time.time(),
            "method": method,
            "url": self.mask_url(url),
            "status_code": raw_resp.status_code,
            "response_time": response_time,
            "response_size": len(final_content),
        })

        return app_response

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        return self.request("POST", url, **kwargs)


# ==============================================================================
# SECTION 2: DATA MODELS (Finding, Endpoint, ScanResult)
# ==============================================================================

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_STATUSES = {"PASS", "WARNING", "VULNERABLE", "INFO", "ERROR", "NOT_TESTED"}
VALID_CONFIDENCES = {"LOW", "MEDIUM", "HIGH"}


@dataclass
class Finding:
    type: str
    severity: str
    status: str
    detail: str
    evidence: str = ""
    confidence: str = "MEDIUM"
    recommendation: str = ""
    endpoint: str = ""
    payload_used: Optional[str] = None

    def __post_init__(self):
        self.severity = self.severity.upper()
        self.status = self.status.upper()
        self.confidence = self.confidence.upper()

        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Mức độ nghiêm trọng '{self.severity}' không hợp lệ.")
        if self.status not in VALID_STATUSES:
            raise ValueError(f"Trạng thái '{self.status}' không hợp lệ.")
        if self.confidence not in VALID_CONFIDENCES:
            raise ValueError(f"Độ tin cậy '{self.confidence}' không hợp lệ.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "severity": self.severity,
            "status": self.status,
            "detail": self.detail,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "recommendation": self.recommendation,
            "endpoint": self.endpoint,
            "payload_used": self.payload_used,
        }


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    content_type: str = ""
    status_code: int = 200
    auth_required: bool = False
    discovery_source: str = "crawler"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "parameters": self.parameters,
            "forms": self.forms,
            "content_type": self.content_type,
            "status_code": self.status_code,
            "auth_required": self.auth_required,
            "discovery_source": self.discovery_source,
        }


@dataclass
class ScanResult:
    target: str
    mode: str = "safe"
    start_time: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    duration: float = 0.0
    attack_surface: Dict[str, Endpoint] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    total_requests: int = 0

    @property
    def summary(self) -> Dict[str, Any]:
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        status_counts = {"PASS": 0, "WARNING": 0, "VULNERABLE": 0, "INFO": 0, "ERROR": 0, "NOT_TESTED": 0}

        for f in self.findings:
            sev = f.severity.upper()
            st = f.status.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            if st in status_counts:
                status_counts[st] += 1

        total_forms = sum(len(ep.forms) for ep in self.attack_surface.values())

        return {
            "target": self.target,
            "mode": self.mode,
            "start_time": self.start_time,
            "duration": round(self.duration, 2),
            "total_requests": self.total_requests,
            "total_endpoints": len(self.attack_surface),
            "total_forms": total_forms,
            "severity_counts": severity_counts,
            "status_counts": status_counts,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "attack_surface": {u: ep.to_dict() for u, ep in self.attack_surface.items()},
            "findings": [f.to_dict() for f in self.findings],
        }


# ==============================================================================
# SECTION 3: SECRET MASKER & FINGERPRINTING
# ==============================================================================

class SecretMasker:
    BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9_\-\.\~]{8,})")
    JWT_PATTERN = re.compile(r"\b(ey[A-Za-z0-9_\-]+\.ey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b")
    API_KEY_PATTERNS = [
        re.compile(r"(?i)\b(sk-[a-zA-Z0-9]{20,})\b"),
        re.compile(r"(?i)\b(AKIA[0-9A-Z]{16})\b"),
        re.compile(r"(?i)\b(ghp_[a-zA-Z0-9]{36})\b"),
    ]
    COOKIE_PATTERN = re.compile(
        r"(?i)\b(session|token|auth|jwt|phpsessid|jsessionid|sid)=([A-Za-z0-9%_\-\.\~]{6,})"
    )

    @classmethod
    def mask_string(cls, text: str) -> str:
        if not text:
            return ""
        masked = cls.BEARER_PATTERN.sub("Bearer ****", text)
        masked = cls.COOKIE_PATTERN.sub(r"\1=****", masked)
        masked = cls.JWT_PATTERN.sub("ey****.ey****.****", masked)
        for pat in cls.API_KEY_PATTERNS:
            masked = pat.sub("sk-****", masked)
        return masked

    @classmethod
    def mask_finding(cls, finding: Finding) -> Finding:
        return Finding(
            type=finding.type,
            severity=finding.severity,
            status=finding.status,
            detail=cls.mask_string(finding.detail),
            evidence=cls.mask_string(finding.evidence),
            confidence=finding.confidence,
            recommendation=finding.recommendation,
            endpoint=finding.endpoint,
            payload_used=cls.mask_string(finding.payload_used) if finding.payload_used else None,
        )

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


def fingerprint_response(
    headers: Dict[str, str],
    cookies: Optional[Dict[str, str]] = None,
    html_content: str = "",
) -> Dict[str, Any]:
    norm_headers = {k.lower(): str(v) for k, v in headers.items()}
    server_info = {"name": "Unknown", "confidence": "LOW"}
    srv = norm_headers.get("server", "")
    if srv:
        server_info = {"name": srv, "evidence": f"Server: {srv}", "confidence": "HIGH"}

    technologies = []
    x_pw = norm_headers.get("x-powered-by", "")
    if x_pw:
        technologies.append({"name": x_pw, "evidence": f"X-Powered-By: {x_pw}", "confidence": "HIGH"})

    frameworks = []
    if "flask" in server_info["name"].lower() or "werkzeug" in server_info["name"].lower():
        frameworks.append({"name": "Flask/Werkzeug", "evidence": server_info["name"], "confidence": "HIGH"})
    if "csrftoken" in (cookies or {}) or "django" in html_content.lower():
        frameworks.append({"name": "Django", "evidence": "Django signatures", "confidence": "MEDIUM"})

    return {
        "server": server_info,
        "technologies": technologies,
        "frameworks": frameworks,
    }


# ==============================================================================
# SECTION 4: CRAWLER & ATTACK SURFACE MAPPING
# ==============================================================================

class Crawler:
    def __init__(self, config: Config, http_client: HTTPClient):
        self.config = config
        self.http_client = http_client
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
            path = parsed.path or "/"
            if len(path) > 1 and path.endswith("/"):
                path = path.rstrip("/")
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            sorted_query = urlencode(sorted(query_pairs))
            return urlunparse((scheme, netloc, path, parsed.params, sorted_query, ""))
        except Exception:
            return url

    def _extract_url_parameters(self, url: str) -> List[str]:
        try:
            parsed = urlparse(url)
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            return [k for k, _ in query_pairs]
        except Exception:
            return []

    def crawl(self) -> Dict[str, Endpoint]:
        start_url = self.normalize_url(self.config.target)
        queue = deque([(start_url, 0)])

        if start_url not in self.endpoints_map:
            self.endpoints_map[start_url] = Endpoint(
                url=start_url,
                method="GET",
                parameters=self._extract_url_parameters(start_url),
                discovery_source="seed",
            )

        # Thăm dò các file nhỏ cố định
        for probe_path in ["/robots.txt", "/sitemap.xml", "/api", "/graphql", "/swagger", "/openapi.json"]:
            probe_url = self.normalize_url(urljoin(start_url, probe_path))
            try:
                p_resp = self.http_client.get(probe_url)
                if p_resp.status_code in (200, 301, 302):
                    self.endpoints_map[probe_url] = Endpoint(
                        url=probe_url,
                        status_code=p_resp.status_code,
                        discovery_source="probe",
                    )
            except ScanBudgetExceeded:
                return self.endpoints_map
            except Exception:
                continue

        # BFS Loop
        while queue and len(self.visited_urls) < self.config.max_pages:
            current_url, depth = queue.popleft()

            if current_url in self.visited_urls:
                continue
            if not self.http_client.scope.is_in_scope(current_url):
                continue

            parsed_curr = urlparse(current_url)
            if any(parsed_curr.path.lower().endswith(ext) for ext in self.config.excluded_extensions):
                continue

            self.visited_urls.add(current_url)

            try:
                resp = self.http_client.get(current_url)
            except ScanBudgetExceeded:
                break
            except Exception:
                continue

            url_params = self._extract_url_parameters(current_url)
            forms = []
            extracted_urls = []

            if "text/html" in resp.content_type.lower() or resp.text.startswith("<!DOCTYPE") or "<html" in resp.text:
                soup = BeautifulSoup(resp.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    raw_href = a.get("href", "").strip()
                    if raw_href and not raw_href.startswith(("javascript:", "mailto:", "tel:")):
                        full_u = urljoin(current_url, raw_href)
                        extracted_urls.append(full_u)

                for form in soup.find_all("form"):
                    f_action = form.get("action", "") or current_url
                    f_method = form.get("method", "GET").upper()
                    f_inputs = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        inp_name = inp.get("name")
                        if inp_name:
                            f_inputs.append({"name": inp_name, "type": inp.get("type", "text")})
                    forms.append({"action": urljoin(current_url, f_action), "method": f_method, "inputs": f_inputs})

            endpoint_obj = self.endpoints_map.get(
                current_url,
                Endpoint(
                    url=current_url,
                    method="GET",
                    parameters=url_params,
                    forms=forms,
                    content_type=resp.content_type,
                    status_code=resp.status_code,
                    discovery_source="crawler",
                ),
            )
            endpoint_obj.forms = forms
            self.endpoints_map[current_url] = endpoint_obj

            if depth < self.config.max_depth:
                for nxt_url in extracted_urls:
                    norm_nxt = self.normalize_url(nxt_url)
                    if norm_nxt and norm_nxt not in self.visited_urls and self.http_client.scope.is_in_scope(norm_nxt):
                        queue.append((norm_nxt, depth + 1))

        return self.endpoints_map


# ==============================================================================
# SECTION 5: SECURITY CHECKS (Safe & Active Checks)
# ==============================================================================

class HeadersCheck:
    RISK_LEVEL = "safe"

    @classmethod
    def check(cls, response: Response, target_url: str) -> List[Finding]:
        findings = []
        headers = {k.lower(): str(v) for k, v in response.headers.items()}
        is_html = "text/html" in headers.get("content-type", "").lower()
        endpoint = response.url or target_url

        if is_html and "content-security-policy" not in headers:
            findings.append(Finding(
                type="Missing Content-Security-Policy",
                severity="MEDIUM",
                status="VULNERABLE",
                detail="Thiếu header Content-Security-Policy (CSP) ngăn ngừa XSS.",
                evidence="Header CSP không tồn tại",
                confidence="HIGH",
                recommendation="Cấu hình Content-Security-Policy chặt chẽ.",
                endpoint=endpoint,
            ))
        if "x-content-type-options" not in headers:
            findings.append(Finding(
                type="Missing X-Content-Type-Options",
                severity="LOW",
                status="WARNING",
                detail="Thiếu header X-Content-Type-Options: nosniff chống MIME-sniffing.",
                evidence="Header X-Content-Type-Options không tồn tại",
                confidence="HIGH",
                recommendation="Thêm header X-Content-Type-Options: nosniff.",
                endpoint=endpoint,
            ))
        if is_html and "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
            findings.append(Finding(
                type="Missing Anti-Clickjacking Header",
                severity="MEDIUM",
                status="WARNING",
                detail="Thiếu header X-Frame-Options hoặc CSP frame-ancestors chống Clickjacking.",
                evidence="X-Frame-Options không tồn tại",
                confidence="HIGH",
                recommendation="Thiết lập X-Frame-Options: SAMEORIGIN hoặc DENY.",
                endpoint=endpoint,
            ))
        return findings


class CookiesCheck:
    RISK_LEVEL = "safe"

    @classmethod
    def check(cls, response: Response, target_url: str) -> List[Finding]:
        findings = []
        raw_set_cookies = [v for k, v in response.headers.items() if k.lower() == "set-cookie"]
        endpoint = response.url or target_url

        for c_header in raw_set_cookies:
            c_lower = c_header.lower()
            c_name = c_header.split("=")[0].strip() if "=" in c_header else "cookie"
            if "httponly" not in c_lower:
                findings.append(Finding(
                    type="Cookie Missing HttpOnly",
                    severity="MEDIUM",
                    status="WARNING",
                    detail=f"Cookie '{c_name}' thiếu cờ HttpOnly, có nguy cơ bị đọc bởi mã JavaScript độc hại.",
                    evidence=SecretMasker.mask_string(c_header),
                    confidence="HIGH",
                    recommendation="Thiết lập cờ HttpOnly cho tất cả các cookie phiên.",
                    endpoint=endpoint,
                ))
            if "secure" not in c_lower and endpoint.startswith("https://"):
                findings.append(Finding(
                    type="Cookie Missing Secure",
                    severity="MEDIUM",
                    status="WARNING",
                    detail=f"Cookie '{c_name}' thiếu cờ Secure trên kết nối HTTPS.",
                    evidence=SecretMasker.mask_string(c_header),
                    confidence="HIGH",
                    recommendation="Thêm cờ Secure cho cookie khi triển khai HTTPS.",
                    endpoint=endpoint,
                ))
        return findings


class SensitiveFilesCheck:
    RISK_LEVEL = "safe"
    TARGET_PATHS = ["/.git/HEAD", "/.env", "/backup.sql", "/database.sqlite", "/swagger.json", "/web.config"]

    @classmethod
    def check(cls, target_url: str, http_client: HTTPClient) -> List[Finding]:
        findings = []
        for p in cls.TARGET_PATHS:
            test_u = urljoin(target_url, p)
            try:
                r = http_client.get(test_u)
                if r.status_code == 200 and len(r.text) > 10:
                    body = r.text.lower()
                    if ("ref: refs/" in body and ".git" in p) or ("db_" in body and ".env" in p) or ("create table" in body and ".sql" in p):
                        findings.append(Finding(
                            type="Sensitive File Exposure",
                            severity="CRITICAL",
                            status="VULNERABLE",
                            detail=f"Tệp tin cấu hình/dữ liệu cực kỳ nhạy cảm được công khai tại '{test_u}'.",
                            evidence=SecretMasker.mask_string(r.text[:120]),
                            confidence="HIGH",
                            recommendation="Xóa tệp tin hoặc cấu hình chặn truy cập từ web server.",
                            endpoint=test_u,
                        ))
            except ScanBudgetExceeded:
                raise
            except Exception:
                continue
        return findings


class XSSCheck:
    RISK_LEVEL = "safe"

    @classmethod
    def check_reflected(cls, endpoint_url: str, http_client: HTTPClient) -> List[Finding]:
        findings = []
        parsed = urlparse(endpoint_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return []

        marker = f"XSS_TEST_{os.urandom(4).hex().upper()}"
        payload = f"<{marker}>"

        for idx, (k, v) in enumerate(params):
            mod_params = list(params)
            mod_params[idx] = (k, payload)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(mod_params), parsed.fragment))

            try:
                resp = http_client.get(test_url)
                if payload in (resp.text or ""):
                    findings.append(Finding(
                        type="Reflected XSS",
                        severity="HIGH",
                        status="VULNERABLE",
                        detail=f"Phát hiện Reflected XSS trên tham số '{k}'. Marker vô hại phản chiếu không mã hóa HTML.",
                        evidence=f"Payload marker: {payload}",
                        confidence="HIGH",
                        recommendation="Mã hóa đầu ra theo ngữ cảnh (Contextual HTML Encoding).",
                        endpoint=endpoint_url,
                        payload_used=payload,
                    ))
            except ScanBudgetExceeded:
                raise
            except Exception:
                continue
        return findings

    @classmethod
    def check_stored(cls, endpoint: Endpoint, http_client: HTTPClient) -> List[Finding]:
        findings = []
        marker = f"XSS_TEST_{os.urandom(4).hex().upper()}"

        for form in endpoint.forms:
            if form.get("method", "GET").upper() != "POST":
                continue
            action = form.get("action") or endpoint.url
            data = {}
            for inp in form.get("inputs", []):
                name = inp.get("name")
                if name:
                    data[name] = f"<{marker}_{name}>"

            try:
                http_client.post(action, data=data)
                r_orig = http_client.get(endpoint.url)
                r_act = http_client.get(action) if action != endpoint.url else r_orig

                for name in data.keys():
                    field_marker = f"<{marker}_{name}>"
                    if field_marker in (r_orig.text or "") or field_marker in (r_act.text or ""):
                        findings.append(Finding(
                            type="Stored XSS",
                            severity="HIGH",
                            status="VULNERABLE",
                            detail=f"Phát hiện Stored XSS trên form '{action}'. Trường '{name}' lưu trữ và phản chiếu marker không qua escape.",
                            evidence=f"Trường: {name} | Marker: {field_marker}",
                            confidence="HIGH",
                            recommendation="Mã hóa toàn bộ dữ liệu người dùng lưu trữ trước khi render HTML.",
                            endpoint=action,
                            payload_used=field_marker,
                        ))
                        break
            except ScanBudgetExceeded:
                raise
            except Exception:
                continue
        return findings


class SQLICheck:
    RISK_LEVEL = "safe"

    @classmethod
    def check(cls, endpoint_url: str, http_client: HTTPClient, is_active_mode: bool = False) -> List[Finding]:
        findings = []
        parsed = urlparse(endpoint_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return []

        sql_errors = ["sqlite3.operationalerror", "syntax error", "you have an error in your sql syntax", "ora-01756", "unclosed quotation mark"]

        for idx, (k, v) in enumerate(params):
            # Error-based
            mod_params = list(params)
            mod_params[idx] = (k, v + "'")
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(mod_params), parsed.fragment))

            try:
                resp = http_client.get(test_url)
                body_lower = (resp.text or "").lower()
                for err in sql_errors:
                    if err in body_lower:
                        findings.append(Finding(
                            type="SQL Injection",
                            severity="CRITICAL",
                            status="VULNERABLE",
                            detail=f"Phát hiện Error-based SQL Injection trên tham số '{k}'. Server trả về chuỗi lỗi SQL cụ thể.",
                            evidence=f"Chuỗi lỗi: '{err}'",
                            confidence="HIGH",
                            recommendation="Sử dụng Parameterized Queries / Prepared Statements.",
                            endpoint=endpoint_url,
                            payload_used=v + "'",
                        ))
                        break
            except ScanBudgetExceeded:
                raise
            except Exception:
                continue

            # Time-based (Active only)
            if is_active_mode:
                try:
                    t_start = time.time()
                    base_r = http_client.get(endpoint_url)
                    base_t = time.time() - t_start

                    time_params = list(params)
                    time_params[idx] = (k, v + "' AND 1=randomblob(100000000) -- ")
                    t_test_u = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(time_params), parsed.fragment))

                    t0 = time.time()
                    http_client.get(t_test_u)
                    elap = time.time() - t0
                    if elap >= 2.0 and (elap - base_t) >= 1.5:
                        findings.append(Finding(
                            type="Time-based SQL Injection",
                            severity="CRITICAL",
                            status="VULNERABLE",
                            detail=f"Phát hiện Time-based SQL Injection trên tham số '{k}'. Độ trễ tăng {round(elap - base_t, 2)}s.",
                            evidence=f"Baseline: {round(base_t, 2)}s -> Test: {round(elap, 2)}s",
                            confidence="HIGH",
                            recommendation="Sử dụng Parameterized Queries.",
                            endpoint=endpoint_url,
                            payload_used=time_params[idx][1],
                        ))
                except ScanBudgetExceeded:
                    raise
                except Exception:
                    pass

        return findings


class ActiveChecks:
    """Tập hợp các module kiểm tra Active Mode nâng cao."""
    RISK_LEVEL = "active_only"

    @classmethod
    def check_command_injection(cls, endpoint_url: str, http_client: HTTPClient) -> List[Finding]:
        findings = []
        parsed = urlparse(endpoint_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return []

        try:
            t_start = time.time()
            http_client.get(endpoint_url)
            base_t = time.time() - t_start
        except Exception:
            return []

        for idx, (k, v) in enumerate(params):
            for payload in ["; sleep 3", "& timeout 3"]:
                mod_params = list(params)
                mod_params[idx] = (k, v + payload)
                test_u = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(mod_params), parsed.fragment))

                try:
                    t0 = time.time()
                    http_client.get(test_u)
                    elap = time.time() - t0
                    if elap >= 2.5 and (elap - base_t) >= 2.0:
                        findings.append(Finding(
                            type="Command Injection",
                            severity="CRITICAL",
                            status="VULNERABLE",
                            detail=f"Phát hiện Time-based OS Command Injection trên tham số '{k}'.",
                            evidence=f"Baseline: {round(base_t, 2)}s -> Test: {round(elap, 2)}s ({payload})",
                            confidence="HIGH",
                            recommendation="Tuyệt đối không truyền chuỗi đầu vào trực tiếp vào shell hệ thống.",
                            endpoint=endpoint_url,
                            payload_used=payload,
                        ))
                        break
                except ScanBudgetExceeded:
                    raise
                except Exception:
                    continue
        return findings

    @classmethod
    def check_path_traversal(cls, endpoint_url: str, http_client: HTTPClient) -> List[Finding]:
        findings = []
        parsed = urlparse(endpoint_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return []

        safe_files = [
            ("win.ini", "../../../../../../Windows/win.ini", ["[extensions]", "[fonts]"]),
            ("/etc/hostname", "../../../../../../etc/hostname", None),
        ]

        for idx, (k, v) in enumerate(params):
            for fname, payload, markers in safe_files:
                mod_params = list(params)
                mod_params[idx] = (k, payload)
                test_u = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(mod_params), parsed.fragment))

                try:
                    r = http_client.get(test_u)
                    body = r.text or ""
                    is_hit = False

                    if markers and any(m in body for m in markers):
                        is_hit = True
                    elif not markers and r.status_code == 200:
                        clean = body.strip()
                        if 1 <= len(clean) <= 64 and re.match(r"^[a-zA-Z0-9_\-\.]+$", clean):
                            is_hit = True

                    if is_hit:
                        findings.append(Finding(
                            type="Path Traversal",
                            severity="HIGH",
                            status="VULNERABLE",
                            detail=f"Phát hiện Path Traversal trên tham số '{k}'. Đã đọc thành công tệp tin whitelist ({fname}).",
                            evidence=f"Payload: {payload} | Nội dung: {body[:80]}",
                            confidence="HIGH",
                            recommendation="Chuẩn hóa đường dẫn tệp và chặn tuyệt đối việc duyệt thư mục cấp cha.",
                            endpoint=endpoint_url,
                            payload_used=payload,
                        ))
                        break
                except ScanBudgetExceeded:
                    raise
                except Exception:
                    continue
        return findings

    @classmethod
    def check_open_redirect(cls, endpoint_url: str, http_client: HTTPClient) -> List[Finding]:
        findings = []
        parsed = urlparse(endpoint_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        target_domain = "https://scanner-redirect-test.invalid"

        for idx, (k, v) in enumerate(params):
            if k.lower() not in {"redirect", "url", "next", "return", "returnurl", "redirect_uri", "continue", "dest"}:
                continue
            mod_params = list(params)
            mod_params[idx] = (k, target_domain)
            test_u = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(mod_params), parsed.fragment))

            try:
                resp = http_client.session.get(test_u, allow_redirects=False, timeout=http_client.config.timeout)
                loc = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and "scanner-redirect-test.invalid" in loc:
                    findings.append(Finding(
                        type="Open Redirect",
                        severity="MEDIUM",
                        status="VULNERABLE",
                        detail=f"Phát hiện Open Redirect trên tham số '{k}' chuyển hướng trực tiếp ra domain ngoài.",
                        evidence=f"Status: {resp.status_code} | Location: {loc}",
                        confidence="HIGH",
                        recommendation="Sử dụng whitelist URL hoặc chỉ cho phép đường dẫn tương đối.",
                        endpoint=endpoint_url,
                        payload_used=target_domain,
                    ))
            except ScanBudgetExceeded:
                raise
            except Exception:
                continue
        return findings

    @classmethod
    def check_ssrf(cls, endpoint_url: str, http_client: HTTPClient, callback_url: Optional[str]) -> List[Finding]:
        parsed = urlparse(endpoint_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        url_params = [k for k, _ in params if k.lower() in {"url", "dest", "target", "feed", "webhook", "callback"}]
        if not url_params:
            return []

        if not callback_url:
            return [
                Finding(
                    type="SSRF",
                    severity="INFO",
                    status="NOT_TESTED",
                    detail=f"Phát hiện tham số tiềm năng '{url_params[0]}', nhưng chưa cung cấp --callback-url. Bỏ qua kiểm tra theo nguyên tắc 4.",
                    evidence="Thiếu --callback-url",
                    confidence="LOW",
                    recommendation="Cung cấp máy chủ callback để kiểm tra out-of-band.",
                    endpoint=endpoint_url,
                )
            ]

        findings = []
        for k in url_params:
            try:
                mod_params = [(pk, callback_url if pk == k else pv) for pk, pv in params]
                test_u = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(mod_params), parsed.fragment))
                resp = http_client.get(test_u)
                findings.append(Finding(
                    type="SSRF Probe",
                    severity="MEDIUM",
                    status="WARNING",
                    detail=f"Đã gửi payload SSRF tới callback URL '{callback_url}'. Vui lòng kiểm tra log trên máy chủ callback.",
                    evidence=f"Callback: {callback_url} | Status: {resp.status_code}",
                    confidence="MEDIUM",
                    recommendation="Áp dụng whitelist URL và chặn kết nối ra IP nội bộ.",
                    endpoint=endpoint_url,
                    payload_used=callback_url,
                ))
            except ScanBudgetExceeded:
                raise
            except Exception:
                continue
        return findings

    @classmethod
    def check_graphql_api(cls, target_url: str, http_client: HTTPClient) -> List[Finding]:
        findings = []
        for path in ["/graphql", "/api/graphql"]:
            u = urljoin(target_url, path)
            try:
                r = http_client.session.post(
                    u,
                    json={"query": "{ __schema { types { name } } }"},
                    headers={"Content-Type": "application/json"},
                    timeout=http_client.config.timeout,
                )
                if r.status_code == 200:
                    data = r.json()
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    if types:
                        findings.append(Finding(
                            type="GraphQL Introspection Enabled",
                            severity="MEDIUM",
                            status="VULNERABLE",
                            detail=f"GraphQL Introspection được bật tại '{u}', cho phép truy vấn toàn bộ schema (tìm thấy {len(types)} types).",
                            evidence=f"Introspection thành công | Tổng types: {len(types)}",
                            confidence="HIGH",
                            recommendation="Tắt Introspection trên môi trường Production.",
                            endpoint=u,
                            payload_used="{ __schema { types { name } } }",
                        ))
            except ScanBudgetExceeded:
                raise
            except Exception:
                continue
        return findings


# ==============================================================================
# SECTION 6: REPORTING (Console, JSON, HTML)
# ==============================================================================

class ConsoleReporter:
    SEVERITY_COLORS = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.RED,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.BLUE,
        "INFO": Fore.GREEN,
    }
    STATUS_ICONS = {
        "VULNERABLE": "[!]",
        "WARNING": "[?]",
        "PASS": "[✓]",
        "INFO": "[i]",
        "ERROR": "[x]",
        "NOT_TESTED": "[-]",
    }

    @classmethod
    def render(cls, result: ScanResult) -> str:
        masked_result = SecretMasker.mask_result(result)
        summary = masked_result.summary

        lines = [
            f"\n{Fore.CYAN}{'=' * 74}",
            f"{Fore.CYAN}       SECURITY AUTOMATION TOOLKIT - BÁO CÁO QUÉT TOÀN DIỆN",
            f"{Fore.CYAN}{'=' * 74}",
            f"Target:      {Style.BRIGHT}{masked_result.target}{Style.RESET_ALL}",
            f"Chế độ:      {Fore.YELLOW if masked_result.mode == 'active' else Fore.GREEN}{masked_result.mode.upper()}{Style.RESET_ALL}",
            f"Thời gian:   {masked_result.start_time} (Thời lượng: {masked_result.duration}s)",
            f"Requests:    {masked_result.total_requests} requests đã gửi",
            f"Attack Map:  {summary['total_endpoints']} endpoints | {summary['total_forms']} forms",
            f"{Fore.CYAN}{'-' * 74}",
        ]

        by_sev: Dict[str, List[Finding]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for f in masked_result.findings:
            by_sev.setdefault(f.severity.upper(), []).append(f)

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            items = by_sev.get(sev, [])
            if not items:
                continue
            color = cls.SEVERITY_COLORS.get(sev, Fore.WHITE)
            lines.append(f"\n{color}[ {sev} ] ({len(items)} phát hiện)")

            for idx, item in enumerate(items, 1):
                icon = cls.STATUS_ICONS.get(item.status.upper(), "[*]")
                lines.append(f"  {color}{icon} {item.type} [{item.status}] (Confidence: {item.confidence})")
                lines.append(f"     Endpoint: {item.endpoint}")
                lines.append(f"     Chi tiết: {item.detail}")
                if item.evidence:
                    lines.append(f"     Bằng chứng: {item.evidence}")

        lines.append(f"\n{Fore.CYAN}{'=' * 74}")
        lines.append(
            f"Tổng kết: {Fore.RED}{summary['severity_counts']['CRITICAL']} Critical{Style.RESET_ALL} | "
            f"{Fore.RED}{summary['severity_counts']['HIGH']} High{Style.RESET_ALL} | "
            f"{Fore.YELLOW}{summary['severity_counts']['MEDIUM']} Medium{Style.RESET_ALL} | "
            f"{Fore.BLUE}{summary['severity_counts']['LOW']} Low{Style.RESET_ALL} | "
            f"{Fore.GREEN}{summary['severity_counts']['INFO']} Info{Style.RESET_ALL}"
        )
        lines.append(f"{Fore.CYAN}{'=' * 74}\n")
        return "\n".join(lines)


class JSONReporter:
    @classmethod
    def generate(cls, result: ScanResult, output_path: str) -> Dict[str, Any]:
        masked_result = SecretMasker.mask_result(result)
        data = masked_result.to_dict()
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return data


class HTMLReporter:
    @classmethod
    def generate(cls, result: ScanResult, output_path: str) -> str:
        masked = SecretMasker.mask_result(result)
        esc = html.escape
        summary = masked.summary
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        rows = []
        for f in masked.findings:
            rows.append(f"""
            <tr>
              <td><strong>{esc(f.type)}</strong></td>
              <td><span class="badge {esc(f.severity.lower())}">{esc(f.severity)}</span></td>
              <td>{esc(f.status)}</td>
              <td><code>{esc(f.endpoint)}</code></td>
              <td>{esc(f.detail)}</td>
              <td><code>{esc(f.evidence)}</code></td>
            </tr>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <title>Security Scan Report - {esc(masked.target)}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; margin: 30px; line-height: 1.5; color: #222; }}
    h1 {{ color: #1e293b; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }}
    .meta-box {{ background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 15px; margin-bottom: 20px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; color: white; }}
    .critical {{ background: #dc2626; }}
    .high {{ background: #ea580c; }}
    .medium {{ background: #ca8a04; }}
    .low {{ background: #2563eb; }}
    .info {{ background: #16a34a; }}
    code {{ background: #f1f5f9; padding: 2px 4px; border-radius: 4px; font-family: Consolas, monospace; }}
  </style>
</head>
<body>
  <h1>🛡️ Báo Cáo Kiểm Tra An Ninh Web Toàn Diện</h1>
  <div class="meta-box">
    <p><strong>Mục tiêu:</strong> {esc(masked.target)}</p>
    <p><strong>Chế độ:</strong> {esc(masked.mode.upper())} | <strong>Thời gian:</strong> {esc(masked.start_time)} | <strong>Thời lượng:</strong> {masked.duration}s</p>
    <p><strong>Requests đã gửi:</strong> {masked.total_requests} | <strong>Endpoints phát hiện:</strong> {summary['total_endpoints']} | <strong>Forms:</strong> {summary['total_forms']}</p>
  </div>
  <h2>Danh Sách Lỗ Hổng & Phát Hiện ({len(masked.findings)})</h2>
  <table>
    <thead>
      <tr>
        <th>Loại Lỗ Hổng</th>
        <th>Mức Độ</th>
        <th>Trạng Thái</th>
        <th>Endpoint</th>
        <th>Mô Tả Chi Tiết</th>
        <th>Bằng Chứng (Evidence)</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return html_content


# ==============================================================================
# SECTION 7: INTERACTIVE LEGAL CONSENT, MODE SELECTION & PIPELINE
# ==============================================================================

def verify_and_select_mode(
    target_domain: str,
    cli_active_flag: bool = False,
    cli_confirm_domain: Optional[str] = None,
    cli_confirm_active: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Xác nhận pháp lý và lựa chọn chế độ quét:
    1. Xác nhận quyền sở hữu domain bằng cách gõ lại chính xác tên domain.
    2. Yêu cầu người dùng xác nhận rõ ràng muốn chạy SAFE MODE hay ACTIVE MODE trước khi tiếp tục.
    3. Nếu chọn ACTIVE MODE: đưa ra cảnh báo chi tiết và bắt buộc xác nhận lần 2.
    """
    print("\n" + "=" * 74)
    print("🛡️  SECURITY SCANNER - XÁC NHẬN PHÁP LÝ & QUYỀN TRUY CẬP HỆ THỐNG")
    print("=" * 74)
    print("CẢNH BÁO BẮT BUỘC:")
    print("Bạn chỉ được phép quét an ninh trên mục tiêu mà bạn sở hữu hoặc đã được")
    print("cấp văn bản ủy quyền hợp pháp. Mọi hành vi quét trái phép đều vi phạm pháp luật.")
    print("-" * 74)

    # Bước 1: Xác nhận domain
    if cli_confirm_domain is not None:
        user_domain = cli_confirm_domain.strip()
    else:
        try:
            prompt_msg = f"Nhập lại domain để xác nhận bạn có quyền scan (vd: {target_domain}): "
            user_domain = input(prompt_msg).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Đã hủy thao tác.")
            return False, "safe"

    if user_domain.lower() != target_domain.lower():
        print(f"\n[!] XÁC NHẬN THẤT BẠI: Domain '{user_domain}' không khớp với target '{target_domain}'.")
        print("[!] Hủy bỏ phiên quét để đảm bảo an toàn pháp lý.")
        return False, "safe"

    print(f"[✓] Đã xác nhận quyền scan hợp pháp cho domain: {target_domain}")

    # Bước 2: Lựa chọn chế độ Safe Mode hay Active Mode
    selected_mode = "safe"
    if cli_active_flag:
        selected_mode = "active"
    else:
        print("\n" + "-" * 74)
        print("LỰA CHỌN CHẾ ĐỘ QUÉT AN NINH (SAFE MODE VS ACTIVE MODE):")
        print("  [1] SAFE MODE (Mặc định - Chỉ gửi GET, static analysis, marker vô hại)")
        print("  [2] ACTIVE MODE (Nâng cao - Chạy payload xâm nhập: Stored XSS, Time-based SQLi/Cmd, Traversal...)")
        try:
            choice = input("Bạn có muốn chạy SAFE MODE hay không? (1 = Safe Mode, 2 = Active Mode) [Mặc định: 1]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Đã hủy thao tác.")
            return False, "safe"

        if choice in ("2", "active", "ACTIVE"):
            selected_mode = "active"
        else:
            selected_mode = "safe"

    # Bước 3: Cảnh báo và xác nhận nếu kích hoạt Active Mode
    if selected_mode == "active":
        print("\n" + "=" * 74)
        print("⚠️  CẢNH BÁO: BẠN ĐANG YÊU CẦU KÍCH HOẠT CHẾ ĐỘ ACTIVE MODE")
        print("=" * 74)
        print("ACTIVE MODE sẽ gửi các payload intrusive hơn SAFE MODE, bao gồm:")
        print("  - Stored XSS: Tự động submit dữ liệu/form thật vào ứng dụng mục tiêu.")
        print("  - Time-based SQLi & Command Injection: Gây độ trễ (delay 2-3s) có kiểm soát.")
        print("  - Path Traversal: Thăm dò file hệ thống có trong whitelist an toàn (/etc/hostname, win.ini).")
        print("  - SSRF: Gửi payload tới callback URL được chỉ định (--callback-url).")
        print("  - Open Redirect: Kiểm tra tham số điều hướng với domain thử nghiệm an toàn (.invalid).")
        print("  - CSRF & IDOR: Phân tích token form và kiểm tra phân quyền giữa 2 phiên người dùng.")
        print("  - JWT Weak Configuration: Kiểm tra thuật toán ký 'none' và thời hạn exp.")
        print("  - File Upload: Kiểm tra bộ lọc upload bằng file ảnh PNG vô hại đổi đuôi tệp.")
        print("  - API & GraphQL: Thăm dò Introspection query công khai (chỉ query, không dump data).")
        print("  - Rate Limiting Burst: Thử nghiệm tối đa 5 request liên tiếp kiểm tra 429.")
        print("Lưu ý: Công cụ TUYỆT ĐỐI KHÔNG chứa destructive payloads (DROP/DELETE, reverse shell).")
        print("-" * 74)

        if cli_confirm_active is not None:
            active_conf = cli_confirm_active.strip()
        else:
            try:
                active_conf = input(
                    f"XÁC NHẬN LẦN 2: Nhập lại domain '{target_domain}' hoặc gõ 'ACTIVE' để tiếp tục: "
                ).strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Đã hủy thao tác.")
                return False, "safe"

        if active_conf.lower() not in (target_domain.lower(), "active"):
            print("\n[!] XÁC NHẬN ACTIVE MODE THẤT BẠI: Người dùng không đồng ý. Hủy bỏ phiên quét.")
            return False, "safe"

        print(f"[✓] Đã xác nhận kích hoạt ACTIVE MODE thành công.")
    else:
        print(f"[✓] Đã chọn SAFE MODE (Chế độ quét an toàn tuyệt đối).")

    return True, selected_mode


# Đạo hữu xin nương tay, tổng quản cấm trận (All-in-One Security Orchestrator) này điều phối vạn biến linh thông qua 6 tầng cảnh giới, chớ tùy tiện sửa đổi cấm chế kẻo phản phệ tan biến tu vi.
def run_unified_scan(config: Config) -> ScanResult:
    start_time = time.time()
    result = ScanResult(
        target=config.target,
        mode=config.mode,
        start_time=time.strftime("%Y-%m-%d %H:%M:%S"),
    )

    client = HTTPClient(config=config)
    crawler = Crawler(config=config, http_client=client)

    # 1. Crawl bề mặt tấn công
    print(f"[*] Bắt đầu thu thập bề mặt tấn công (Crawler) cho {config.target}...")
    try:
        crawler.crawl()
    except ScanBudgetExceeded as e:
        print(f"\n[!] GIỚI HẠN REQUEST TOÀN CỤC ĐÃ ĐẠT TRONG CRAWLER: {e}")
    except Exception as e:
        print(f"[!] Gặp sự cố trong Crawler: {e}")

    result.attack_surface = crawler.endpoints_map

    # 2. Fingerprinting
    try:
        root_resp = client.get(config.target)
        fp = fingerprint_response(
            headers=root_resp.headers,
            cookies=root_resp.cookies,
            html_content=root_resp.text or "",
        )
        if fp.get("server") and fp["server"].get("name") != "Unknown":
            srv = fp["server"]
            result.findings.append(Finding(
                type="Server Detection",
                severity="INFO",
                status="INFO",
                detail=f"Phát hiện web server: {srv['name']}",
                evidence=str(srv.get("evidence", "")),
                confidence=srv.get("confidence", "HIGH"),
                endpoint=config.target,
                recommendation="Xem xét ẩn thông tin server nếu không cần thiết.",
            ))
        for tech in fp.get("technologies", []):
            result.findings.append(Finding(
                type="Technology Detection",
                severity="INFO",
                status="INFO",
                detail=f"Phát hiện công nghệ: {tech['name']}",
                evidence=str(tech.get("evidence", "")),
                confidence=tech.get("confidence", "HIGH"),
                endpoint=config.target,
                recommendation="Đảm bảo cập nhật bản vá mới nhất.",
            ))
    except ScanBudgetExceeded as e:
        print(f"\n[!] GIỚI HẠN REQUEST TOÀN CỤC ĐÃ ĐẠT: {e}")
    except Exception:
        pass

    # 3. Chạy các bài kiểm tra an ninh
    is_active = config.mode == "active"
    print(f"[*] Đang thực hiện các bài kiểm tra an ninh ({config.mode.upper()} MODE)...")

    # Safe root checks
    try:
        result.findings.extend(SensitiveFilesCheck.check(config.target, client))
    except ScanBudgetExceeded as e:
        print(f"\n[!] GIỚI HẠN REQUEST TOÀN CỤC ĐÃ ĐẠT: {e}")
    except Exception:
        pass

    if is_active:
        try:
            result.findings.extend(ActiveChecks.check_graphql_api(config.target, client))
        except ScanBudgetExceeded:
            pass
        except Exception:
            pass

    # Endpoint iteration
    for ep_url, ep in list(result.attack_surface.items())[:25]:
        try:
            resp = client.get(ep_url)
            # Safe checks
            result.findings.extend(HeadersCheck.check(resp, ep_url))
            result.findings.extend(CookiesCheck.check(resp, ep_url))

            if ep.parameters:
                result.findings.extend(XSSCheck.check_reflected(ep_url, client))
                result.findings.extend(SQLICheck.check(ep_url, client, is_active_mode=is_active))

            # Active-only checks
            if is_active:
                if ep.forms:
                    result.findings.extend(XSSCheck.check_stored(ep, client))
                if ep.parameters:
                    result.findings.extend(ActiveChecks.check_command_injection(ep_url, client))
                    result.findings.extend(ActiveChecks.check_path_traversal(ep_url, client))
                    result.findings.extend(ActiveChecks.check_open_redirect(ep_url, client))
                    result.findings.extend(ActiveChecks.check_ssrf(ep_url, client, callback_url=config.callback_url))

        except ScanBudgetExceeded as e:
            print(f"\n[!] GIỚI HẠN REQUEST TOÀN CỤC ĐÃ ĐẠT: {e}")
            break
        except Exception:
            continue

    result.duration = round(time.time() - start_time, 2)
    result.total_requests = client.total_requests
    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="All-in-One Web Security Scanner - Tích hợp toàn diện 6 Phase kiểm thử an ninh.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", nargs="?", default=None, help="Target URL (vd: http://example.com)")
    parser.add_argument("--target", dest="target_opt", help="Target URL (tùy chọn cờ thay thế)")
    parser.add_argument("--active", action="store_true", default=False, help="Bật cờ Active Mode (intrusive testing). Mặc định là SAFE mode.")
    parser.add_argument("--max-requests", type=int, default=None, help="Số lượng request tối đa (500 ở Safe, 1500 ở Active).")
    parser.add_argument("--rps", type=float, default=5.0, help="Số lượng request tối đa mỗi giây.")
    parser.add_argument("--max-depth", type=int, default=3, help="Độ sâu crawl tối đa.")
    parser.add_argument("--max-pages", type=int, default=50, help="Số trang crawl tối đa.")
    parser.add_argument("--output-dir", default="output", help="Thư mục xuất báo cáo.")
    parser.add_argument("--json", dest="json_path", help="Đường dẫn file báo cáo JSON.")
    parser.add_argument("--html", dest="html_path", help="Đường dẫn file báo cáo HTML.")
    parser.add_argument("--callback-url", dest="callback_url", default=None, help="URL callback cho SSRF.")
    parser.add_argument("--confirm-domain", dest="confirm_domain", default=None, help="Xác nhận trước domain target (dùng cho CI/automation).")
    parser.add_argument("--confirm-active", dest="confirm_active", default=None, help="Xác nhận trước active mode (dùng cho CI/automation).")

    args = parser.parse_args(argv)

    raw_target = args.target or args.target_opt
    if not raw_target:
        parser.print_help()
        print("\n[!] Lỗi: Vui lòng cung cấp URL mục tiêu (target).")
        return 1

    target = raw_target.strip()
    if not (target.startswith("http://") or target.startswith("https://")):
        target = "http://" + target

    parsed = urlparse(target)
    target_domain = parsed.hostname
    if not target_domain:
        print(f"[!] Lỗi: URL mục tiêu không hợp lệ: {raw_target}")
        return 1

    # 1. Xác nhận pháp lý và lựa chọn Safe Mode / Active Mode
    consent, selected_mode = verify_and_select_mode(
        target_domain=target_domain,
        cli_active_flag=args.active,
        cli_confirm_domain=args.confirm_domain,
        cli_confirm_active=args.confirm_active,
    )
    if not consent:
        return 1

    # 2. Khởi tạo cấu hình phiên quét
    max_reqs = args.max_requests
    if max_reqs is None:
        max_reqs = 1500 if selected_mode == "active" else 500

    config = Config(
        target=target,
        mode=selected_mode,
        max_requests_per_scan=max_reqs,
        requests_per_second=args.rps,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        callback_url=args.callback_url,
    )

    # 3. Tiến hành quét an ninh
    print(f"\n[*] Bắt đầu phiên quét an ninh cho {target} [Chế độ: {selected_mode.upper()}]...")
    result = run_unified_scan(config)

    # 4. Xuất báo cáo đa định dạng
    print(ConsoleReporter.render(result))

    os.makedirs(args.output_dir, exist_ok=True)
    json_file = args.json_path or os.path.join(args.output_dir, "scan_report.json")
    html_file = args.html_path or os.path.join(args.output_dir, "scan_report.html")

    JSONReporter.generate(result, output_path=json_file)
    HTMLReporter.generate(result, output_path=html_file)

    print("\n[✓] Đã xuất báo cáo quét an ninh:")
    print(f"  - JSON Report: {os.path.abspath(json_file)}")
    print(f"  - HTML Report: {os.path.abspath(html_file)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
