import re
from typing import Any, Dict, List, Optional, Set


class TechnologyFingerprinter:
    # Đạo hữu xin nương tay, thần thông biện thức căn nguyên (Technology Identification) này đang phân định linh căn hệ thống, chớ dại vọng động làm nhiễu loạn ngũ hành.
    @classmethod
    def identify(
        cls,
        headers: Dict[str, str],
        cookies: Optional[Dict[str, str]] = None,
        body: str = "",
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        identified_names: Set[str] = set()

        lower_headers = {k.lower(): str(v) for k, v in headers.items()}
        powered_by = lower_headers.get("x-powered-by", "").strip()
        server_val = lower_headers.get("server", "").strip()
        server_lower = server_val.lower()
        powered_by = lower_headers.get("x-powered-by", "").strip()
        powered_by_lower = powered_by.lower()
        set_cookie = lower_headers.get("set-cookie", "").strip()

        cookie_names = set()
        if cookies:
            cookie_names.update([c.lower() for c in cookies.keys()])
        if set_cookie:
            for part in set_cookie.split(";"):
                if "=" in part:
                    cname = part.split("=")[0].strip().lower()
                    cookie_names.add(cname)

        # 1. PHP
        php_evidence = []
        if "php" in powered_by_lower:
            php_evidence.append(f"X-Powered-By: {powered_by}")
        if "phpsessid" in cookie_names:
            php_evidence.append("Cookie: PHPSESSID")
        if ".php" in body[:500].lower():
            php_evidence.append("HTML source: .php extension")
        if php_evidence:
            conf = "HIGH" if len(php_evidence) > 1 else "MEDIUM"
            results.append({
                "name": "PHP",
                "confidence": conf,
                "evidence": "; ".join(php_evidence),
            })
            identified_names.add("PHP")

        # 2. Python
        python_evidence = []
        if "python" in server_lower:
            python_evidence.append(f"Server: {server_val}")
        if "werkzeug" in server_lower or "gunicorn" in server_lower:
            python_evidence.append(f"Server header: {server_val}")
        if "session" in cookie_names and ("werkzeug" in server_lower or "flask" in server_lower):
            python_evidence.append("Cookie: session (Flask-like)")
        if python_evidence:
            conf = "HIGH" if any("python" in e.lower() for e in python_evidence) else "MEDIUM"
            results.append({
                "name": "Python",
                "confidence": conf,
                "evidence": "; ".join(python_evidence),
            })
            identified_names.add("Python")

        # 3. Java
        java_evidence = []
        if "jsessionid" in cookie_names:
            java_evidence.append("Cookie: JSESSIONID")
        if "tomcat" in server_val or "jboss" in server_val or "jetty" in server_val:
            java_evidence.append(f"Server: {server_val}")
        if java_evidence:
            conf = "HIGH" if len(java_evidence) > 1 else "MEDIUM"
            results.append({
                "name": "Java",
                "confidence": conf,
                "evidence": "; ".join(java_evidence),
            })
            identified_names.add("Java")

        # 4. Node.js
        node_evidence = []
        if "express" in powered_by:
            node_evidence.append(f"X-Powered-By: {powered_by}")
        if "connect.sid" in cookie_names or "sails.sid" in cookie_names:
            node_evidence.append("Cookie: connect.sid/sails.sid")
        if node_evidence:
            conf = "HIGH" if len(node_evidence) > 1 else "MEDIUM"
            results.append({
                "name": "Node.js",
                "confidence": conf,
                "evidence": "; ".join(node_evidence),
            })
            identified_names.add("Node.js")

        # 5. .NET / ASP.NET
        dotnet_evidence = []
        if "asp.net" in powered_by or "x-aspnet-version" in lower_headers:
            dotnet_evidence.append(f"Header: {powered_by or lower_headers.get('x-aspnet-version')}")
        if "asp.net_sessionid" in cookie_names:
            dotnet_evidence.append("Cookie: ASP.NET_SessionId")
        if "__viewstate" in body.lower():
            dotnet_evidence.append("HTML: __VIEWSTATE input present")
        if dotnet_evidence:
            conf = "HIGH" if len(dotnet_evidence) > 1 else "MEDIUM"
            results.append({
                "name": ".NET / ASP.NET",
                "confidence": conf,
                "evidence": "; ".join(dotnet_evidence),
            })
            identified_names.add(".NET / ASP.NET")

        # 6. Ruby
        ruby_evidence = []
        if "phusion passenger" in server_val or "rack" in lower_headers.get("x-runtime", ""):
            ruby_evidence.append(f"Header: {server_val}")
        if "_rails_session" in cookie_names:
            ruby_evidence.append("Cookie: _rails_session")
        if ruby_evidence:
            conf = "MEDIUM"
            results.append({
                "name": "Ruby",
                "confidence": conf,
                "evidence": "; ".join(ruby_evidence),
            })
            identified_names.add("Ruby")

        return results
