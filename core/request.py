from dataclasses import dataclass, field
import time
from typing import Any, Dict, Optional


@dataclass
class Request:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    params: Optional[Dict[str, Any]] = None
    data: Optional[Any] = None
    json: Optional[Any] = None
    timeout: float = 10.0
    timestamp: float = field(default_factory=time.time)
