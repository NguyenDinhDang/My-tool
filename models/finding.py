from dataclasses import dataclass, field
from typing import Any, Dict, Optional


VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_STATUSES = {"PASS", "WARNING", "VULNERABLE", "INFO", "ERROR", "NOT_TESTED"}
VALID_CONFIDENCES = {"LOW", "MEDIUM", "HIGH"}


@dataclass
class Finding:
    type: str
    severity: str
    status: str
    detail: str
    evidence: str = ""
    confidence: str = "MEDIUM"
    recommendation: str = ""
    endpoint: str = ""
    payload_used: Optional[str] = None

    def __post_init__(self):
        self.severity = self.severity.upper()
        self.status = self.status.upper()
        self.confidence = self.confidence.upper()

        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Mức độ nghiêm trọng '{self.severity}' không hợp lệ. Cho phép: {VALID_SEVERITIES}")
        if self.status not in VALID_STATUSES:
            raise ValueError(f"Trạng thái '{self.status}' không hợp lệ. Cho phép: {VALID_STATUSES}")
        if self.confidence not in VALID_CONFIDENCES:
            raise ValueError(f"Độ tin cậy '{self.confidence}' không hợp lệ. Cho phép: {VALID_CONFIDENCES}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "severity": self.severity,
            "status": self.status,
            "detail": self.detail,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "recommendation": self.recommendation,
            "endpoint": self.endpoint,
            "payload_used": self.payload_used,
        }
