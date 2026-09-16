from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import List, Optional


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
    max_pages: int = 100
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
