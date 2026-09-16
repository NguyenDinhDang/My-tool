from urllib.parse import urlparse
from typing import Iterable, Set


class ScopeViolationError(Exception):
    """Bắn ra khi một URL cố gắng vượt ra ngoài phạm vi (scope) được cấp phép."""
    pass


class Scope:
    def __init__(self, allowed_domains: Iterable[str]):
        self._allowed_domains: Set[str] = set()
        for d in allowed_domains:
            clean_d = self._normalize_domain(d)
            if clean_d:
                self._allowed_domains.add(clean_d)

    @property
    def allowed_domains(self) -> Set[str]:
        return set(self._allowed_domains)

    def _normalize_domain(self, domain_or_url: str) -> str:
        d = domain_or_url.strip().lower()
        if "://" in d:
            parsed = urlparse(d)
            d = parsed.netloc or parsed.path
        if ":" in d:
            d = d.split(":", 1)[0]
        return d.strip("/")

    def is_in_scope(self, url: str) -> bool:
        if not url:
            return False

        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if not host:
                return False

            host = host.lower()

            # Đạo hữu xin nương tay, kết giới hộ sơn (Scope boundary) này phân định cõi giới cực kỳ nghiêm ngặt, chớ dại mà sửa đổi kẻo thần thức tán loạn, dẫn yêu nhập thất.
            for allowed in self._allowed_domains:
                if host == allowed or host.endswith("." + allowed):
                    return True
            return False
        except Exception:
            return False
