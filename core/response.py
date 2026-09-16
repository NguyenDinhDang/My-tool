from dataclasses import dataclass, field
from typing import Dict, List, Optional
from core.request import Request


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

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600
