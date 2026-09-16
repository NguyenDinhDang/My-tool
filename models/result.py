from dataclasses import dataclass, field
import time
from typing import Any, Dict, List
from models.endpoint import Endpoint
from models.finding import Finding


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
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        status_counts = {
            "PASS": 0,
            "WARNING": 0,
            "VULNERABLE": 0,
            "INFO": 0,
            "ERROR": 0,
            "NOT_TESTED": 0,
        }

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
