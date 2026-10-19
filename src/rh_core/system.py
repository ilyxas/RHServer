"""Mac load for sys.* data sources (SPEC §5.4), behind an interface.

`PsutilProbe` reads the real system without sudo; `FakeProbe` returns fixed
values for tests and for `rhcore dev up --fixture`.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

import psutil

# psutil measures CPU between two calls. When the previous call is older than
# this, the reading would be an average over minutes; take a short fresh sample.
CPU_STALE_S = 5.0
CPU_SAMPLE_S = 0.3


class SystemProbe(Protocol):
    def cpu_percent(self) -> float: ...

    def memory_percent(self) -> float: ...

    def disk_free(self) -> int: ...


class PsutilProbe:
    def __init__(
        self, disk_path: str = "/", *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.disk_path = disk_path
        self._clock = clock
        self._lock = threading.Lock()
        self._last: float | None = None

    def cpu_percent(self) -> float:
        """Whole-Mac CPU load, 0..100. May block for CPU_SAMPLE_S: call off the event loop."""
        with self._lock:
            stale = self._last is None or self._clock() - self._last > CPU_STALE_S
            value = psutil.cpu_percent(interval=CPU_SAMPLE_S if stale else None)
            self._last = self._clock()
            return float(value)

    def memory_percent(self) -> float:
        return float(psutil.virtual_memory().percent)

    def disk_free(self) -> int:
        """Bytes free on the startup volume (APFS volumes share the container's space)."""
        return int(psutil.disk_usage(self.disk_path).free)


@dataclass
class FakeProbe:
    cpu: float = 12.5
    memory: float = 48.0
    disk: int = 112_400_000_000

    def cpu_percent(self) -> float:
        return self.cpu

    def memory_percent(self) -> float:
        return self.memory

    def disk_free(self) -> int:
        return self.disk
