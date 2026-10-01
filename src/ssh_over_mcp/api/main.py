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
        host="127.0.0.1",
        port=settings.port,
    )


if __name__ == "__main__":
    main()
