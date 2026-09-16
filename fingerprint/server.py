import re
from typing import Any, Dict, List, Optional


class ServerFingerprinter:
    KNOWN_SERVERS = [
        ("Werkzeug", re.compile(r"""werkzeug(?:/([0-9\.]+))?""", re.IGNORECASE)),
        ("Nginx", re.compile(r"""nginx(?:/([0-9\.]+))?""", re.IGNORECASE)),
        ("Apache", re.compile(r"""apache(?:/([0-9\.]+))?""", re.IGNORECASE)),
        ("Microsoft-IIS", re.compile(r"""microsoft-iis(?:/([0-9\.]+))?""", re.IGNORECASE)),
        ("Gunicorn", re.compile(r"""gunicorn(?:/([0-9\.]+))?""", re.IGNORECASE)),
        ("Caddy", re.compile(r"""caddy(?:/([0-9\.]+))?""", re.IGNORECASE)),
        ("Cloudflare", re.compile(r"""cloudflare""", re.IGNORECASE)),
        ("LiteSpeed", re.compile(r"""litespeed""", re.IGNORECASE)),
        ("OpenResty", re.compile(r"""openresty(?:/([0-9\.]+))?""", re.IGNORECASE)),
        ("uWSGI", re.compile(r"""uwsgi""", re.IGNORECASE)),
    ]

    # Đạo hữu xin nương tay, trận đồ xem tướng sơn môn (Server Fingerprinting) này đang dòm ngó khí tức môn phái, chớ nghịch bừa kẻo hộ sơn đại trận phản phệ.
    @classmethod
    def identify(cls, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        lower_headers = {k.lower(): v for k, v in headers.items()}
        server_val = lower_headers.get("server", "").strip()
        via_val = lower_headers.get("via", "").strip()
        x_server_val = lower_headers.get("x-server", "").strip()

        combined_evidence = []
        if server_val:
            combined_evidence.append(f"Server: {server_val}")
        if via_val:
            combined_evidence.append(f"Via: {via_val}")
        if x_server_val:
            combined_evidence.append(f"X-Server: {x_server_val}")

        if not combined_evidence:
            return None

        search_text = " ".join([server_val, via_val, x_server_val])

        for name, pattern in cls.KNOWN_SERVERS:
            match = pattern.search(search_text)
            if match:
                version = match.group(1) if match.lastindex and match.group(1) else None
                evidence_str = "; ".join(combined_evidence)

                # Quyết định độ tin cậy
                if version and ("server:" in evidence_str.lower() and "via:" in evidence_str.lower()):
                    confidence = "HIGH"
                elif version:
                    confidence = "MEDIUM"
                else:
                    # Chỉ có tên generic -> LOW
                    confidence = "LOW"

                return {
                    "name": name,
                    "version": version,
                    "confidence": confidence,
                    "evidence": evidence_str,
                }

        # Nếu có header Server nhưng không khớp signature cụ thể nào
        if server_val:
            return {
                "name": server_val.split("/")[0],
                "version": server_val.split("/")[1] if "/" in server_val else None,
                "confidence": "LOW",
                "evidence": f"Server: {server_val}",
            }

        return None
