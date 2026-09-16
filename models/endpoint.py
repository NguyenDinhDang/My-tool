from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    content_type: str = ""
    status_code: int = 200
    auth_required: bool = False
    technology: Dict[str, Any] = field(default_factory=dict)
    discovery_source: str = "crawl"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "parameters": sorted(list(set(self.parameters))),
            "forms": self.forms,
            "content_type": self.content_type,
            "status_code": self.status_code,
            "auth_required": self.auth_required,
            "technology": self.technology,
            "discovery_source": self.discovery_source,
        }
