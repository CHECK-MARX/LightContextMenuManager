from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional


class SettingsManager:
    """Lightweight JSON-backed settings."""

    DEFAULTS: Dict[str, Any] = {"audit_enabled": True}

    def __init__(self, path: Path, logger: Optional[logging.Logger] = None):
        self.path = path
        self.logger = logger or logging.getLogger(__name__)
        self.data: Dict[str, Any] = dict(self.DEFAULTS)
        self._load()

    def _load(self):
        if not self.path.exists():
            self._write_defaults()
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            self.logger.warning("settings.json is invalid JSON, recreating with defaults.")
            self._write_defaults()
            return
        if isinstance(payload, dict):
            self.data.update(payload)
        else:
            self.logger.warning("settings.json must contain a JSON object. Using defaults.")

    def _write_defaults(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.DEFAULTS, indent=2, ensure_ascii=False), encoding="utf-8")

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def audit_enabled(self) -> bool:
        return bool(self.data.get("audit_enabled", True))
