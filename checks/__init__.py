from typing import Dict, List
from core.config import Config
from core.http_client import HTTPClient
from core.rate_limiter import ScanBudgetExceeded
from models.endpoint import Endpoint
from models.finding import Finding

from checks.headers import HeadersCheck
from checks.cookies import CookiesCheck
from checks.tls import TLSCheck
from checks.cors import CORSCheck
from checks.sensitive_files import SensitiveFilesCheck
from checks.information_disclosure import InformationDisclosureCheck
from checks.http_methods import HTTPMethodsCheck
from checks.xss import XSSCheck
from checks.sqli import SQLICheck
from checks.nosqli import NoSQLICheck

# Phase 6 Active Checks
from checks.command_injection import CommandInjectionCheck
from checks.traversal import PathTraversalCheck
from checks.ssrf import SSRFCheck
from checks.redirect import OpenRedirectCheck
from checks.csrf import CSRFCheck
from checks.idor import IDORCheck
from checks.jwt import JWTCheck
from checks.upload import FileUploadCheck
from checks.api import APICheck
from checks.rate_limit import RateLimitCheck

RISK_LEVEL = "safe"


def run_checks(
    http_client: HTTPClient,
    config: Config,
    attack_surface: Dict[str, Endpoint],
) -> List[Finding]:
    """
    Điều phối chạy toàn bộ bộ kiểm tra an ninh:
    - Safe checks (Headers, Cookies, TLS, CORS, Sensitive Files, Info Disclosure, HTTP Methods, Reflected/DOM XSS, Error/Union SQLi, NoSQLi).
    - Active checks (Stored XSS, Time-based SQLi, Command Injection, Path Traversal, SSRF, Open Redirect, CSRF, IDOR, JWT, File Upload, API, Rate Limit)
      CHỈ CHẠY KHI config.mode == 'active'.
    """
    all_findings: List[Finding] = []
    target_url = config.target
    is_active = config.mode == "active"

    # 1. TLS / SSL Check (Safe)
    try:
        all_findings.extend(TLSCheck.check(target_url, http_client))
    except ScanBudgetExceeded:
        return all_findings
    except Exception:
        pass

    # 2. Sensitive Files Check (Safe)
    try:
        all_findings.extend(SensitiveFilesCheck.check(target_url, http_client))
    except ScanBudgetExceeded:
        return all_findings
    except Exception:
        pass

    # 3. HTTP Methods & CORS Check trên target root (Safe)
    try:
        all_findings.extend(HTTPMethodsCheck.check(target_url, http_client))
        all_findings.extend(CORSCheck.check(target_url, http_client))
    except ScanBudgetExceeded:
        return all_findings
    except Exception:
        pass

    # 4. Root-level Active Checks (CHỈ KHI is_active == True)
    if is_active:
        try:
            all_findings.extend(APICheck.check(target_url, http_client, is_active_mode=True))
            all_findings.extend(RateLimitCheck.check(target_url, http_client, is_active_mode=True))
        except ScanBudgetExceeded:
            return all_findings
        except Exception:
            pass

    # 5. Duyệt qua các endpoint trong attack surface
    endpoints_to_check = list(attack_surface.values())[:20]

    for ep in endpoints_to_check:
        ep_url = ep.url

        try:
            resp = http_client.get(ep_url)
            html_content = resp.text or ""
            resp_cookies = resp.cookies or {}

            # A. Safe Passive / Non-intrusive Checks
            all_findings.extend(HeadersCheck.check(resp, ep_url))
            all_findings.extend(CookiesCheck.check(resp, ep_url))
            all_findings.extend(InformationDisclosureCheck.check(resp, ep_url))
            all_findings.extend(XSSCheck.check_dom_xss(html_content, ep_url))

            # B. Reflected XSS (Safe - marker vô hại trên query params)
            if ep.parameters:
                all_findings.extend(XSSCheck.check_reflected(ep_url, http_client))

            # C. SQL Injection (Safe Error/Union/Boolean, Time-based chỉ khi is_active=True)
            if ep.parameters:
                all_findings.extend(SQLICheck.check(ep_url, http_client, is_active_mode=is_active))

            # D. NoSQL Injection (Safe operator injection trên JSON endpoint)
            all_findings.extend(NoSQLICheck.check_json_endpoint(ep, http_client))

            # E. ACTIVE-ONLY CHECKS (Chỉ chạy khi is_active == True)
            if is_active:
                # E1. Stored XSS (submit form POST đúng 1 lần với marker)
                if ep.forms:
                    all_findings.extend(XSSCheck.check_stored(ep, http_client, is_active_mode=True))

                # E2. Command Injection (Time-based vô hại)
                if ep.parameters:
                    all_findings.extend(CommandInjectionCheck.check(ep_url, http_client, is_active_mode=True))

                # E3. Path Traversal (Whitelist files)
                if ep.parameters:
                    all_findings.extend(PathTraversalCheck.check(ep_url, http_client, is_active_mode=True))

                # E4. SSRF (Callback URL hoặc NOT_TESTED)
                if ep.parameters:
                    all_findings.extend(SSRFCheck.check(
                        ep_url,
                        http_client,
                        callback_url=config.callback_url,
                        is_active_mode=True,
                    ))

                # E5. Open Redirect (.invalid domain)
                if ep.parameters:
                    all_findings.extend(OpenRedirectCheck.check(ep_url, http_client, is_active_mode=True))

                # E6. CSRF (Phân tích form & SameSite cookie)
                if ep.forms:
                    all_findings.extend(CSRFCheck.check(ep, html_content, resp_cookies, is_active_mode=True))

                # E7. IDOR (Yêu cầu 2 sessions hoặc NOT_TESTED)
                if ep.parameters:
                    all_findings.extend(IDORCheck.check(
                        ep_url,
                        http_client,
                        auth_cookie_a=config.auth_cookie_a,
                        auth_cookie_b=config.auth_cookie_b,
                        auth_header_a=config.auth_header_a,
                        auth_header_b=config.auth_header_b,
                        is_active_mode=True,
                    ))

                # E8. JWT Check
                all_findings.extend(JWTCheck.check(ep_url, http_client, is_active_mode=True))

                # E9. File Upload Check
                if ep.forms:
                    all_findings.extend(FileUploadCheck.check(ep, http_client, html_content, is_active_mode=True))

        except ScanBudgetExceeded:
            break
        except Exception:
            continue

    return all_findings


def run_safe_checks(
    http_client: HTTPClient,
    config: Config,
    attack_surface: Dict[str, Endpoint],
) -> List[Finding]:
    """Tương thích ngược: chạy các checks ở chế độ safe."""
    return run_checks(http_client, config, attack_surface)


__all__ = [
    "RISK_LEVEL",
    "HeadersCheck",
    "CookiesCheck",
    "TLSCheck",
    "CORSCheck",
    "SensitiveFilesCheck",
    "InformationDisclosureCheck",
    "HTTPMethodsCheck",
    "XSSCheck",
    "SQLICheck",
    "NoSQLICheck",
    "CommandInjectionCheck",
    "PathTraversalCheck",
    "SSRFCheck",
    "OpenRedirectCheck",
    "CSRFCheck",
    "IDORCheck",
    "JWTCheck",
    "FileUploadCheck",
    "APICheck",
    "RateLimitCheck",
    "run_checks",
    "run_safe_checks",
]
