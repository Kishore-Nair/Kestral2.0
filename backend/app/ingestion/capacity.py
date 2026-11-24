"""Single-process scan admission control for the demo worker."""

from threading import BoundedSemaphore, Lock


class ScanCapacity:
    def __init__(self, limit: int) -> None:
        if limit <= 0:
            raise ValueError("Scan capacity must be positive")
        self.limit = limit
        self._semaphore = BoundedSemaphore(limit)
        self._active = 0
        self._lock = Lock()

    @property
    def active(self) -> int:
        with self._lock:
            return self._active

    def reserve(self) -> bool:
        if not self._semaphore.acquire(blocking=False):
            return False
        with self._lock:
            self._active += 1
        return True

    def release(self) -> None:
        with self._lock:
            if self._active <= 0:
                raise RuntimeError("No reserved scan slot to release")
            self._active -= 1
        self._semaphore.release()
