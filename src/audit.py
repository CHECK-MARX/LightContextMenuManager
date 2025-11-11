from __future__ import annotations

import csv
import getpass
import logging
import platform
from datetime import datetime
from pathlib import Path
from typing import Optional


class AuditLogger:
    """Append-only CSV logger for user operations."""

    headers = [
        "timestamp",
        "user",
        "machine",
        "action",
        "item_name",
        "scope",
        "result",
        "error",
    ]

    def __init__(self, directory: Path, *, enabled: bool = True, logger: Optional[logging.Logger] = None):
        self.directory = directory
        self.enabled = enabled
        self.logger = logger or logging.getLogger(__name__)
        self.user = getpass.getuser()
        self.machine = platform.node()

    def log(
        self,
        *,
        action: str,
        item_name: str,
        scope: str,
        result: str,
        error: str = "",
    ):
        if not self.enabled:
            return
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            filename = self.directory / f"audit_{datetime.now():%Y%m%d}.csv"
            file_exists = filename.exists()
            with filename.open("a", encoding="utf-8-sig", newline="") as handle:
                writer = csv.writer(handle, lineterminator="\r\n")
                if not file_exists:
                    writer.writerow(self.headers)
                writer.writerow(
                    [
                        datetime.now().isoformat(timespec="seconds"),
                        self.user,
                        self.machine,
                        action,
                        item_name,
                        scope,
                        result,
                        error,
                    ]
                )
        except Exception as exc:  # pragma: no cover - logging must never break the app
            self.logger.warning("Failed to append audit log: %s", exc)
