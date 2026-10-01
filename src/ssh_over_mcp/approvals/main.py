from __future__ import annotations

import signal
import threading

from .runtime import SecurityLedgerRuntimeSettings
from .service import SecurityLedgerService


def main() -> None:
    settings = SecurityLedgerRuntimeSettings.from_env()
    stop = threading.Event()

    def request_stop(_signum, _frame) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    with SecurityLedgerService.create(settings) as service:
        service.serve_forever(stop_requested=stop.is_set)


if __name__ == "__main__":
    main()
