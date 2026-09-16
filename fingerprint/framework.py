import re
from typing import Any, Dict, List, Optional


class FrameworkFingerprinter:
    # Đạo hữu xin nương tay, chiêu thức chiếu yêu kính (Framework Fingerprinting) này phân biệt các đại phái khung pháp, chớ vội vàng quyết đoán kẻo nhận lầm đồng đạo.
    @classmethod
    def identify(
        cls,
        headers: Dict[str, str],
        cookies: Optional[Dict[str, str]] = None,
        html_content: str = "",
        meta_tags: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        lower_headers = {k.lower(): str(v) for k, v in headers.items()}
        server_val = lower_headers.get("server", "").lower()
        powered_by = lower_headers.get("x-powered-by", "").lower()
        set_cookie = lower_headers.get("set-cookie", "").lower()
        body_lower = html_content.lower() if html_content else ""

        cookie_names = set()
        if cookies:
            cookie_names.update([c.lower() for c in cookies.keys()])
        if set_cookie:
            for part in set_cookie.split(";"):
                if "=" in part:
                    cname = part.split("=")[0].strip()
                    cookie_names.add(cname)

        meta = meta_tags or {}
        generator = meta.get("generator", "").lower()

        # 1. WordPress
        wp_evidence = []
        if "wordpress" in generator:
            wp_evidence.append(f"Meta generator: {meta.get('generator')}")
        if "wp-content" in body_lower or "wp-includes" in body_lower:
            wp_evidence.append("HTML: wp-content or wp-includes detected")
        if wp_evidence:
            conf = "HIGH" if "wordpress" in generator else "MEDIUM"
            results.append({
                "name": "WordPress",
                "confidence": conf,
                "evidence": "; ".join(wp_evidence),
            })

        # 2. Flask (Python)
        flask_evidence = []
        if "werkzeug" in server_val:
            flask_evidence.append(f"Server header: {lower_headers.get('server')}")
        if "flask" in server_val or "flask" in powered_by:
            flask_evidence.append("Header explicit Flask")
        if "session" in cookie_names and "werkzeug" in server_val:
            flask_evidence.append("Cookie session with Werkzeug WSGI server")
        if flask_evidence:
            # Nếu chỉ thấy Werkzeug mà không thấy gì khác -> MEDIUM cho Flask
            conf = "HIGH" if ("flask" in server_val or len(flask_evidence) > 1) else "MEDIUM"
            results.append({
                "name": "Flask",
                "confidence": conf,
                "evidence": "; ".join(flask_evidence),
            })

        # 3. Django (Python)
        django_evidence = []
        if "csrftoken" in cookie_names:
            django_evidence.append("Cookie: csrftoken (Django standard)")
        if "django" in generator:
            django_evidence.append(f"Meta generator: {meta.get('generator')}")
        if django_evidence:
            conf = "HIGH" if len(django_evidence) > 1 else "MEDIUM"
            results.append({
                "name": "Django",
                "confidence": conf,
                "evidence": "; ".join(django_evidence),
            })

        # 4. Laravel (PHP)
        laravel_evidence = []
        if "laravel_session" in cookie_names or "xsrf-token" in cookie_names and "laravel" in body_lower:
            laravel_evidence.append("Cookie: laravel_session / xsrf-token")
        if "laravel" in powered_by:
            laravel_evidence.append(f"X-Powered-By: {lower_headers.get('x-powered-by')}")
        if laravel_evidence:
            conf = "HIGH" if len(laravel_evidence) > 1 else "MEDIUM"
            results.append({
                "name": "Laravel",
                "confidence": conf,
                "evidence": "; ".join(laravel_evidence),
            })

        # 5. Next.js / React
        react_evidence = []
        if "__next" in body_lower or "_next/static" in body_lower:
            react_evidence.append("HTML: Next.js __next structure or _next/static scripts")
            results.append({
                "name": "Next.js",
                "confidence": "HIGH",
                "evidence": "; ".join(react_evidence),
            })
        elif "data-reactroot" in body_lower or "_react" in body_lower:
            results.append({
                "name": "React",
                "confidence": "MEDIUM",
                "evidence": "HTML: data-reactroot attribute",
            })

        # 6. Express (Node.js)
        if "express" in powered_by:
            results.append({
                "name": "Express",
                "confidence": "HIGH",
                "evidence": f"X-Powered-By: {lower_headers.get('x-powered-by')}",
            })

        return results
