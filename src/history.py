from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class HistoryEntry:
    """Represents a single enable/disable toggle."""

    name: str
    registry_path: str
    key_name: str
    base_path: str
    scope: str
    from_enabled: bool
    to_enabled: bool
    timestamp: str

    @classmethod
    def from_dict(cls, data: dict) -> "HistoryEntry":
        return cls(
            name=data.get("name", ""),
            registry_path=data.get("registry_path", ""),
            key_name=data.get("key_name", ""),
            base_path=data.get("base_path", ""),
            scope=data.get("scope", ""),
            from_enabled=bool(data.get("from_enabled", False)),
            to_enabled=bool(data.get("to_enabled", False)),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


class HistoryManager:
    """Undo/redo stack persisted to disk (read-only on startup)."""

    def __init__(self, limit: int = 100):
        self.limit = limit
        self._undo: List[HistoryEntry] = []
        self._redo: List[HistoryEntry] = []
        self._recent_snapshot: List[HistoryEntry] = []

    # Stack helpers ------------------------------------------------------
    def record(
        self,
        *,
        name: str,
        registry_path: str,
        key_name: str,
        base_path: str,
        scope: str,
        from_enabled: bool,
        to_enabled: bool,
    ):
        entry = HistoryEntry(
            name=name,
            registry_path=registry_path,
            key_name=key_name,
            base_path=base_path,
            scope=scope,
            from_enabled=from_enabled,
            to_enabled=to_enabled,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self._undo.append(entry)
        if len(self._undo) > self.limit:
            self._undo.pop(0)
        self._redo.clear()

    def undo(self) -> Optional[HistoryEntry]:
        if not self._undo:
            return None
        entry = self._undo.pop()
        self._redo.append(entry)
        return entry

    def redo(self) -> Optional[HistoryEntry]:
        if not self._redo:
            return None
        entry = self._redo.pop()
        self._undo.append(entry)
        return entry

    def can_undo(self) -> bool:
        return bool(self._undo)

    def can_redo(self) -> bool:
        return bool(self._redo)

    # Persistence --------------------------------------------------------
    def load_snapshot(self, path: Path):
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return
        snapshot = data.get("recent", []) if isinstance(data, dict) else data
        self._recent_snapshot = [HistoryEntry.from_dict(item) for item in snapshot[-self.limit :]]

    def save_snapshot(self, path: Path):
        payload = {"recent": [asdict(entry) for entry in self._undo[-self.limit :]]}
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    # Introspection ------------------------------------------------------
    def last_entries(self) -> List[HistoryEntry]:
        return list(self._undo)

    def snapshot_entries(self) -> List[HistoryEntry]:
        return list(self._recent_snapshot)
