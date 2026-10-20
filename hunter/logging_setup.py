"""Daily log file plus stderr. One file per UTC day."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path


class DailyFileHandler(logging.Handler):
    """Append to logs/hunter_YYYYMMDD.log, rolling when the UTC date changes."""

    hunter_daily = True

    def __init__(self, directory: Path):
        super().__init__()
        self.directory = directory
        self._day: str | None = None
        self._file: logging.FileHandler | None = None

    def emit(self, record: logging.LogRecord) -> None:
        try:
            day = datetime.now(timezone.utc).strftime("%Y%m%d")
            if day != self._day or self._file is None:
                if self._file is not None:
                    self._file.close()
                self.directory.mkdir(parents=True, exist_ok=True)
                path = self.directory / f"hunter_{day}.log"
                self._file = logging.FileHandler(path, encoding="utf-8")
                self._file.setFormatter(self.formatter)
                self._day = day
            self._file.emit(record)
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
        super().close()


def configure_logging(directory: Path | None = None) -> Path:
    """Attach stderr and a daily file handler once. Returns the log directory."""
    folder = directory or Path(os.environ.get("HUNTER_LOG_DIR", "logs"))
    root = logging.getLogger()
    if any(getattr(handler, "hunter_daily", False) for handler in root.handlers):
        return folder
    root.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    daily = DailyFileHandler(folder)
    daily.setFormatter(formatter)
    root.handlers.clear()
    root.addHandler(stream)
    root.addHandler(daily)
    return folder
