from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Literal, Optional

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QSortFilterProxyModel
from PySide6.QtGui import QIcon


@dataclass
class HandlerEntry:
    """Represents a single context menu handler row."""

    name: str
    type: Literal["verb", "shellex"]
    type: Literal["verb", "shellex"]
    scope: str
    key_name: str
    registry_path: str
    full_key_path: str
    base_path: str
    base_rel_path: str
    enabled: bool
    last_modified: Optional[datetime]
    last_write_time: Optional[datetime]
    status: str
    read_only: bool = False
    command: Optional[str] = None
    normalized_name: str = ""
    normalized_command: Optional[str] = None
    icon: Optional[QIcon] = None
    target_path: Optional[str] = None
    tooltip: str = ""
    clsid: Optional[str] = None
    is_quarantined: bool = False
    quarantine_meta: Optional[Dict[str, str]] = None

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
        elif role == Qt.DecorationRole and column == 1:
            return entry.icon
        elif role == Qt.ToolTipRole:
            return entry.tooltip
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
        self._favorites_only = False
        self._type_filter: Optional[str] = None
        self._scope_filter: Optional[str] = None
        self.setFilterCaseSensitivity(Qt.CaseInsensitive)

    def set_keyword(self, keyword: str):
        self._keyword = keyword.strip()
        # invalidate() supersedes invalidateFilter() in Qt6
        self.invalidate()

    def set_favorites_only(self, enabled: bool):
        self._favorites_only = enabled
        self.invalidate()

    def set_type_filter(self, handler_type: Optional[str]):
        self._type_filter = handler_type
        self.invalidate()

    def set_scope_filter(self, scope: Optional[str]):
        self._scope_filter = scope
        self.invalidate()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # type: ignore[override]
        model: HandlerTableModel = self.sourceModel()  # type: ignore[assignment]
        entry = model.entry_at(source_row)
        if not entry:
            return False
        if self._favorites_only and not entry.is_favorite:
            return False
        if self._type_filter and entry.type != self._type_filter:
            return False
        if self._scope_filter and entry.scope != self._scope_filter:
            return False
        haystack = "|".join(
            [
                entry.name,
                entry.key_name,
                entry.scope,
                entry.registry_path,
                entry.base_path,
                entry.status,
                entry.target_path or "",
            ]
        )
        if self._keyword and self._keyword.lower() not in haystack.lower():
            return False
        return True
