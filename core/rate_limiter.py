import time
import threading


class ScanBudgetExceeded(Exception):
    """Bắn ra khi phiên quét đã chạm ngưỡng giới hạn request toàn cục (global budget)."""
    pass


class RateLimiter:
    def __init__(self, max_requests_per_scan: int = 500, requests_per_second: float = 5.0):
        self.max_requests_per_scan = max_requests_per_scan
        self.requests_per_second = requests_per_second
        self._total_requests = 0
        self._last_request_time = 0.0
        self._lock = threading.Lock()

    @property
    def total_requests(self) -> int:
        with self._lock:
            return self._total_requests

    @property
    def current_count(self) -> int:
        with self._lock:
            return self._total_requests

    @property
    def remaining_budget(self) -> int:
        with self._lock:
            return max(0, self.max_requests_per_scan - self._total_requests)

    def acquire(self):
        with self._lock:
            if self._total_requests >= self.max_requests_per_scan:
                raise ScanBudgetExceeded(
                    f"Đã đạt giới hạn request tối đa cho phiên quét: "
                    f"{self._total_requests}/{self.max_requests_per_scan}"
                )

            # Đạo hữu xin nương tay, trận pháp định tâm (Rate Limiter) điều tức linh khí vận hành ổn định, chớ dại nhiễu loạn thiên cơ kẻo đan điền bạo phát tẩu hỏa nhập ma.
            if self.requests_per_second > 0:
                min_interval = 1.0 / self.requests_per_second
                now = time.time()
                elapsed = now - self._last_request_time
                if elapsed < min_interval:
                    time.sleep(min_interval - elapsed)
                self._last_request_time = time.time()

            self._total_requests += 1

    def reset(self):
        with self._lock:
            self._total_requests = 0
            self._last_request_time = 0.0
