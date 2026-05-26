"""Rate Limiter and In-Memory TTL Cache for Threat Intelligence Providers.

Prevents API quota exhaustion, enforces provider limits, and caches
threat lookups with configurable time-to-live.
"""

import time
import threading
from typing import Dict, Any, Optional, Tuple


class SlidingWindowRateLimiter:
    """Thread-safe sliding window rate limiter."""
    def __init__(self, requests_per_minute: int):
        self.rpm = max(1, requests_per_minute)
        self.window_seconds = 60.0
        self.requests = []
        self._lock = threading.Lock()

    def acquire(self, block: bool = True, timeout: float = 15.0) -> bool:
        """Attempts to acquire rate limit slot. If block is True, waits up to timeout."""
        start_wait = time.time()
        while True:
            with self._lock:
                now = time.time()
                # Clean up timestamps older than 60s
                self.requests = [ts for ts in self.requests if now - ts < self.window_seconds]
                
                if len(self.requests) < self.rpm:
                    self.requests.append(now)
                    return True
                
                if not block:
                    return False
                
                oldest = self.requests[0]
                wait_time = (oldest + self.window_seconds) - now
            
            if time.time() - start_wait + wait_time > timeout:
                return False
                
            if wait_time > 0:
                time.sleep(min(wait_time + 0.1, 1.0))


class MemoryTTLCache:
    """Thread-safe in-memory cache with expiration timestamps."""
    def __init__(self, default_ttl_seconds: int = 3600):
        self.default_ttl = default_ttl_seconds
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._cache:
                return None
            expiry, value = self._cache[key]
            if time.time() > expiry:
                del self._cache[key]
                return None
            return value

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        with self._lock:
            self._cache[key] = (time.time() + ttl, value)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        with self._lock:
            now = time.time()
            # Clean expired
            self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
            return len(self._cache)


# Global cache instance
threat_cache = MemoryTTLCache(default_ttl_seconds=3600)
