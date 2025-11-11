from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QSortFilterProxyModel


@dataclass
class HandlerEntry:
    """Represents a single context menu handler row."""

    name: str
    key_name: str
    scope: str
    registry_path: str
    base_path: str
    enabled: bool
    last_modified: Optional[datetime]
    status: str
    read_only: bool = False

    def to_csv_row(self) -> List[str]:
        timestamp = self.last_modified.isoformat(sep=" ") if self.last_modified else ""
        return [self.name, self.scope, self.status, self.registry_path, timestamp]


class HandlerTableModel(QAbstractTableModel):
    """Qt table model that exposes HandlerEntry metadata to the view."""

    headers = [
        "",  # checkbox column
        "名前",
        "スコープ",
        "元パス",
        "状態",
        "レジストリパス",
        "最終変更",
    ]

    def __init__(self, entries: Optional[List[HandlerEntry]] = None):
        super().__init__()
        self._entries: List[HandlerEntry] = entries or []

    # Qt model overrides -------------------------------------------------
    def rowCount(self, parent: QModelIndex | None = None) -> int:  # type: ignore[override]
        if parent and parent.isValid():
            return 0
        return len(self._entries)

    def columnCount(self, parent: QModelIndex | None = None) -> int:  # type: ignore[override]
        return len(self.headers)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):  # type: ignore[override]
        if not index.isValid():
            return None

        entry = self._entries[index.row()]
        column = index.column()

        if role == Qt.DisplayRole:
            if column == 0:
                return ""
            if column == 1:
                return entry.name
            if column == 2:
                return entry.scope
            if column == 3:
                return entry.base_path
            if column == 4:
                return entry.status
            if column == 5:
                return entry.registry_path
            if column == 6:
                if entry.last_modified:
                    return entry.last_modified.strftime("%Y-%m-%d %H:%M:%S")
                return ""
        elif role == Qt.CheckStateRole and column == 0:
            return Qt.Checked if entry.enabled else Qt.Unchecked
        elif role == Qt.TextAlignmentRole and column in (2, 3, 4, 5, 6):
            return Qt.AlignCenter

        return None

    def setData(self, index: QModelIndex, value, role: int = Qt.EditRole):  # type: ignore[override]
        if not index.isValid():
            return False
        if index.column() == 0 and role == Qt.CheckStateRole:
            entry = self._entries[index.row()]
            entry.enabled = value == Qt.Checked
            entry.status = "有効" if entry.enabled else "無効"
            self.dataChanged.emit(index, index, [Qt.CheckStateRole, Qt.DisplayRole])
            return True
        return False

    def flags(self, index: QModelIndex):  # type: ignore[override]
        if not index.isValid():
            return Qt.ItemIsEnabled
        flags = super().flags(index)
        if index.column() == 0:
            flags |= Qt.ItemIsUserCheckable | Qt.ItemIsEditable
        return flags

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):  # type: ignore[override]
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return super().headerData(section, orientation, role)

    # Helpers -------------------------------------------------------------
    def entries(self) -> List[HandlerEntry]:
        return list(self._entries)

    def entry_at(self, row: int) -> Optional[HandlerEntry]:
        if 0 <= row < len(self._entries):
            return self._entries[row]
        return None

    def update_entries(self, entries: List[HandlerEntry]):
        self.beginResetModel()
        self._entries = entries
        self.endResetModel()


class HandlerFilterProxyModel(QSortFilterProxyModel):
    """Filters handlers by the search keyword in multiple columns."""

    def __init__(self):
        super().__init__()
        self._keyword = ""
        self.setFilterCaseSensitivity(Qt.CaseInsensitive)

    def set_keyword(self, keyword: str):
        self._keyword = keyword.strip()
        # invalidate() supersedes invalidateFilter() in Qt6
        self.invalidate()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # type: ignore[override]
        if not self._keyword:
            return True

        model: HandlerTableModel = self.sourceModel()  # type: ignore[assignment]
        entry = model.entry_at(source_row)
        if not entry:
            return False
        haystack = "|".join([entry.name, entry.key_name, entry.scope, entry.registry_path, entry.base_path, entry.status])
        return self._keyword.lower() in haystack.lower()
