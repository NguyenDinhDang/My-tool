from typing import Any, Dict, Optional
from fingerprint.server import ServerFingerprinter
from fingerprint.technology import TechnologyFingerprinter
from fingerprint.framework import FrameworkFingerprinter


def fingerprint_response(
    headers: Dict[str, str],
    cookies: Optional[Dict[str, str]] = None,
    html_content: str = "",
    meta_tags: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Tổng hợp nhận diện server, công nghệ và framework cho một phản hồi HTTP."""
    server_info = ServerFingerprinter.identify(headers)
    technologies = TechnologyFingerprinter.identify(headers, cookies, html_content)
    frameworks = FrameworkFingerprinter.identify(headers, cookies, html_content, meta_tags)

    return {
        "server": server_info,
        "technologies": technologies,
        "frameworks": frameworks,
    }


__all__ = [
    "ServerFingerprinter",
    "TechnologyFingerprinter",
    "FrameworkFingerprinter",
    "fingerprint_response",
]
