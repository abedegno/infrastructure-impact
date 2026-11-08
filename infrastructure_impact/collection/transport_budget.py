"""Shared, monotonic accounting for a caller-bounded retrieval operation."""


class TransportBudget:
    def __init__(self, max_attempts: int, max_received_bytes: int):
        for value in (max_attempts, max_received_bytes):
            if type(value) is not int or value < 0:
                raise ValueError("Transport limits must be nonnegative integers")
        self._max_attempts = max_attempts
        self._max_received_bytes = max_received_bytes
        self._attempts = 0
        self._received_bytes = 0

    @property
    def attempts(self) -> int:
        return self._attempts

    @property
    def received_bytes(self) -> int:
        return self._received_bytes

    @property
    def remaining_received_bytes(self) -> int:
        return self._max_received_bytes - self._received_bytes

    def start_attempt(self) -> None:
        if self._attempts >= self._max_attempts:
            raise ValueError("HTTP attempt budget exhausted")
        self._attempts += 1

    def consume_received(self, size: int) -> None:
        if type(size) is not int or size < 0:
            raise ValueError("Received size must be a nonnegative integer")
        if size > self.remaining_received_bytes:
            raise ValueError("HTTP received body budget exhausted")
        self._received_bytes += size
