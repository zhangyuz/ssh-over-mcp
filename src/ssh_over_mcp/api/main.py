from __future__ import annotations

import os

import uvicorn

from .app import build_application
from .runtime import load_runtime_settings


def main() -> None:
    settings = load_runtime_settings(os.environ)
    application = build_application(settings)
    uvicorn.run(
        application,
        host=settings.bind_host,
        port=settings.port,
    )


if __name__ == "__main__":
    main()
