from __future__ import annotations

import logging
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

def _load_theme_module():
    try:
        import qdarktheme as theme_module  # type: ignore
        return theme_module
    except ImportError:
        try:
            import pyqtdarktheme as theme_module  # type: ignore
            return theme_module
        except ImportError:
            class _Fallback:
                @staticmethod
                def setup_theme(theme_name: str):
                    logging.getLogger(__name__).warning(
                        "No dark theme package available; skipping theme setup for '%s'.",
                        theme_name,
                    )

            return _Fallback()


qdarktheme = _load_theme_module()

try:
    from PySide6 import QtConcurrent

    _HAS_QTCONCURRENT = hasattr(QtConcurrent, "run")
except ImportError:  # pragma: no cover - optional dependency on some wheels
    QtConcurrent = None  # type: ignore[assignment]
    _HAS_QTCONCURRENT = False

from PySide6.QtCore import QModelIndex, Qt, QTimer, Slot, QSettings
from PySide6.QtGui import QAction, QColor, QKeySequence, QPixmap
from PySide6.QtWidgets import (
    QFileDialog,
    QHeaderView,
    QLineEdit,
    QMainWindow,
    QDialog,
    QTreeWidget,
    QTreeWidgetItem,
    QHBoxLayout,
    QVBoxLayout,
    QFormLayout,
    QLabel,
    QPushButton,
    QRadioButton,
    QCheckBox,
    QMessageBox,
    QProgressDialog,
    QStatusBar,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QToolBar,
    QWidget,
    QComboBox,
    QMenu,
    QApplication,
    QDialogButtonBox,
    QFrame,
    QSplitter,
    QScrollArea,
)

from ..audit import AuditLogger
from ..history import HistoryEntry, HistoryManager
from ..models import HandlerEntry, HandlerFilterProxyModel, HandlerTableModel
from ..presets import Preset, PresetManager
from ..registry import DuplicateGroup, RegistryManager, export_to_reg, group_duplicates


@dataclass
class PlannedChange:
    name: str
    scope: str
    before: bool
    after: bool


class MainWindow(QMainWindow):
    """Main application window that wires UI actions to registry operations."""

    def __init__(
        self,
        *,
        registry: RegistryManager,
        history: HistoryManager,
        history_path: Path,
        presets: PresetManager,
        audit_logger: AuditLogger,
        audit_path: Path,
        settings,
        logger: Optional[logging.Logger] = None,
    ):
        super().__init__()
        self.registry = registry
        self.history = history
        self.history_path = history_path
        self.presets = presets
        self.audit_logger = audit_logger
        self.audit_path = audit_path
        self.settings = settings
        self.logger = logger or logging.getLogger(__name__)

        self.setWindowTitle("Light Context Menu Manager")
        self.resize(1200, 700)

        self.model = HandlerTableModel()
        self.proxy = HandlerFilterProxyModel()
        self.proxy.setSourceModel(self.model)
        self._settings_storage = QSettings("CursorSoft", "LightContextMenuManager")
        self._simple_view_enabled = self.settings.simple_view_enabled() if hasattr(self.settings, "simple_view_enabled") else True

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.ExtendedSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableView.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.clicked.connect(self._handle_table_click)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.doubleClicked.connect(self._handle_row_double_click)
        self.table.selectionModel().selectionChanged.connect(self._on_table_selection_changed)
        self._apply_simple_view_mode(self._simple_view_enabled)
        self.table.doubleClicked.connect(self._handle_row_double_click)

        self._create_preview_panel()
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.table)
        splitter.addWidget(self.preview_panel)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)

        container = QWidget()
        layout = QHBoxLayout(container)
        layout.addWidget(splitter)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setCentralWidget(container)

        self.toolbar = QToolBar("ツールバー", self)
        self.addToolBar(Qt.TopToolBarArea, self.toolbar)
        self._build_toolbar()

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self._safety_label = QLabel()
        self.status.addPermanentWidget(self._safety_label)
        self._update_safety_status()

        self._pending_timers: List[QTimer] = []
        self._executor = ThreadPoolExecutor(max_workers=4)
        self.current_theme = "dark"
        qdarktheme.setup_theme("dark")

        loaded = len(self.history.snapshot_entries())
        if loaded:
            self.status.showMessage(f"履歴 {loaded} 件を読み込みました (読み取り専用)", 6000)

        self.refresh_entries()

    # ------------------------------------------------------------------ #
    # UI construction
    # ------------------------------------------------------------------ #
    def _build_toolbar(self):
        self.search_field = QLineEdit(self)
        self.search_field.setPlaceholderText("検索...")
        self.search_field.textChanged.connect(self.proxy.set_keyword)
        self.toolbar.addWidget(self.search_field)

        self.action_detect_duplicates = QAction("重複を検出", self)
        self.action_detect_duplicates.triggered.connect(self.on_detect_duplicates)
        self.toolbar.addAction(self.action_detect_duplicates)

        self.new_handler_action = QAction("新規メニュー追加(&N)…", self)
        self.new_handler_action.triggered.connect(self._add_new_handler)
        self.toolbar.addAction(self.new_handler_action)

        self.favorite_filter_action = QAction("★のみ", self, checkable=True)
        self.favorite_filter_action.toggled.connect(self.proxy.set_favorites_only)
        self.toolbar.addAction(self.favorite_filter_action)

        self.shellex_filter_action = QAction("ShellEx", self, checkable=True)
        self.shellex_filter_action.toggled.connect(self._on_shellex_filter_toggled)
        self.toolbar.addAction(self.shellex_filter_action)

        self.shell_filter_action = QAction("shell/verb", self, checkable=True)
        self.shell_filter_action.toggled.connect(self._on_shell_filter_toggled)
        self.toolbar.addAction(self.shell_filter_action)

        self.broken_filter_action = QAction("壊れている項目のみ", self, checkable=True)
        self.broken_filter_action.toggled.connect(self._on_broken_filter_toggled)
        self.toolbar.addAction(self.broken_filter_action)
        self.simple_view_action = QAction("シンプル表示(&S)", self, checkable=True)
        self.simple_view_action.setChecked(self._simple_view_enabled)
        self.simple_view_action.toggled.connect(self._on_simple_view_toggled)
        self.toolbar.addAction(self.simple_view_action)

        self.scope_combo = QComboBox(self)
        self.scope_combo.addItem("スコープ: すべて", None)
        self.scope_combo.currentIndexChanged.connect(self._on_scope_filter_changed)
        self.toolbar.addWidget(self.scope_combo)

        reload_action = QAction("再読み込み", self)
        reload_action.setShortcut(QKeySequence.Refresh)
        reload_action.triggered.connect(self.refresh_entries)
        self.toolbar.addAction(reload_action)

        self.undo_action = QAction("元に戻す", self)
        self.undo_action.setShortcut(QKeySequence.Undo)
        self.undo_action.triggered.connect(self.undo_last_action)
        self.undo_action.setEnabled(False)
        self.toolbar.addAction(self.undo_action)

        self.redo_action = QAction("やり直し", self)
        self.redo_action.setShortcut(QKeySequence.Redo)
        self.redo_action.triggered.connect(self.redo_last_action)
        self.redo_action.setEnabled(False)
        self.toolbar.addAction(self.redo_action)

        backup_action = QAction("バックアップ(.reg)", self)
        backup_action.triggered.connect(self.backup_entries)
        self.toolbar.addAction(backup_action)

        restore_action = QAction("復元(.reg)", self)
        restore_action.triggered.connect(self.restore_from_file)
        self.toolbar.addAction(restore_action)

        csv_action = QAction("CSV出力", self)
        csv_action.triggered.connect(self.export_csv)
        self.toolbar.addAction(csv_action)

        self.preset_combo = QComboBox(self)
        self._populate_preset_combo()
        self.preset_combo.currentIndexChanged.connect(self._preset_selected)
        self.toolbar.addWidget(self.preset_combo)

        explorer_action = QAction("Explorer再起動", self)
        explorer_action.setShortcut(QKeySequence("Ctrl+Shift+E"))
        explorer_action.triggered.connect(self.restart_explorer)
        self.toolbar.addAction(explorer_action)

        theme_action = QAction("テーマ切替", self, checkable=True)
        theme_action.setChecked(True)
        theme_action.triggered.connect(self.toggle_theme)
        self.toolbar.addAction(theme_action)

        audit_action = QAction("監査フォルダを開く", self)
        audit_action.triggered.connect(self.open_audit_folder)
        self.toolbar.addAction(audit_action)

        edit_action = QAction("編集", self)
        edit_action.setShortcut(QKeySequence("Ctrl+Return"))
        edit_action.triggered.connect(self._toggle_selected_entry)
        self.addAction(edit_action)

        open_registry_action = QAction("レジストリキーを開く", self)
        open_registry_action.setShortcut(QKeySequence("Ctrl+R"))
        open_registry_action.triggered.connect(self._open_selected_registry)
        self.addAction(open_registry_action)

    def _populate_preset_combo(self):
        self.preset_combo.clear()
        self.preset_combo.addItem("プリセット適用", None)
        for preset in self.presets.list_presets():
            self.preset_combo.addItem(preset.label, preset.preset_id)

    @Slot()
    def on_detect_duplicates(self):
        entries = self.model.entries()
        groups = group_duplicates(entries)
        if not groups:
            QMessageBox.information(self, "重複を検出", "重複は見つかりませんでした。")
            return
        dlg = DuplicateDialog(groups, self.registry, self)
        if dlg.exec() == QDialog.Accepted:
            quarantined, errors = dlg.run_quarantine_with_backup()
            if errors:
                QMessageBox.warning(
                    self,
                    "重複の整理",
                    f"隔離 {quarantined} 件、エラー {len(errors)} 件\n詳細はログを確認してください。",
                )
            else:
                QMessageBox.information(
                    self, "重複の整理", f"隔離 {quarantined} 件を完了しました。"
                )
            ret = QMessageBox.question(
                self,
                "Explorer の再起動",
                "変更を反映するには Explorer の再起動が必要です。再起動しますか？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if ret == QMessageBox.Yes:
                self.restart_explorer()
            self.refresh_entries()
            self._prompt_restart_explorer()

    def _prompt_restart_explorer(self):
        ret = QMessageBox.question(
            self,
            "Explorer の再起動",
            "変更を反映するには Explorer の再起動が必要です。再起動しますか？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if ret == QMessageBox.Yes:
            self.restart_explorer()

    def _add_new_handler(self):
        dialog = NewHandlerDialog(
            registry=self.registry,
            on_created=self.refresh_entries,
            parent=self,
        )
        if dialog.exec() == QDialog.Accepted:
            self.status.showMessage("新しいメニューを作成しました。", 4000)
            self._prompt_restart_explorer()
    def _sort_entries(self, entries: List[HandlerEntry]) -> List[HandlerEntry]:
        return sorted(
            entries,
            key=lambda e: (
                bool(not e.is_favorite),
                e.scope.lower(),
                e.name.lower(),
            ),
        )

    def _reorder_entries(self):
        entries = self.model.entries()
        self.model.update_entries(self._sort_entries(entries))

    def _toggle_favorite_entry(self, entry: HandlerEntry):
        new_state = not entry.is_favorite
        entry.is_favorite = new_state
        self.settings.set_favorite(entry.registry_path, new_state)
        self._reorder_entries()

    def _update_scope_filter_options(self, entries: List[HandlerEntry]):
        scopes = sorted({entry.scope for entry in entries})
        current = self.scope_combo.currentData()
        self.scope_combo.blockSignals(True)
        self.scope_combo.clear()
        self.scope_combo.addItem("スコープ: すべて", None)
        for scope in scopes:
            self.scope_combo.addItem(scope, scope)
        target_index = 0
        if current is not None:
            idx = self.scope_combo.findData(current)
            if idx >= 0:
                target_index = idx
        self.scope_combo.setCurrentIndex(target_index)
        self.scope_combo.blockSignals(False)
        self.proxy.set_scope_filter(self.scope_combo.itemData(target_index))

    def _on_shellex_filter_toggled(self, checked: bool):
        if checked:
            self.shell_filter_action.blockSignals(True)
            self.shell_filter_action.setChecked(False)
            self.shell_filter_action.blockSignals(False)
            self.proxy.set_type_filter("shellex")
        elif not self.shell_filter_action.isChecked():
            self.proxy.set_type_filter(None)
        self._refresh_preview()

    def _on_shell_filter_toggled(self, checked: bool):
        if checked:
            self.shellex_filter_action.blockSignals(True)
            self.shellex_filter_action.setChecked(False)
            self.shellex_filter_action.blockSignals(False)
            self.proxy.set_type_filter("shell")
        elif not self.shellex_filter_action.isChecked():
            self.proxy.set_type_filter(None)
        self._refresh_preview()

    def _on_scope_filter_changed(self, index: int):
        value = self.scope_combo.itemData(index)
        self.proxy.set_scope_filter(value)
        self._refresh_preview()

    def _preset_selected(self, index: int):
        if index <= 0:
            return
        preset_id = self.preset_combo.itemData(index)
        preset = self.presets.get(preset_id) if preset_id else None
        if preset:
            self.apply_preset(preset)
        self.preset_combo.setCurrentIndex(0)

    # ------------------------------------------------------------------ #
    # Core actions
    # ------------------------------------------------------------------ #
    def refresh_entries(self):
        self._run_in_background(
            description="レジストリをスキャン中...",
            func=self.registry.scan_handlers,
            on_success=self._apply_entries,
        )

    def _apply_entries(self, entries: List[HandlerEntry]):
        favorites = set(self.settings.favorites())
        for entry in entries:
            entry.is_favorite = entry.registry_path in favorites
        sorted_entries = self._sort_entries(entries)
        self.model.update_entries(sorted_entries)
        self._update_scope_filter_options(sorted_entries)
        self.table.resizeColumnsToContents()
        self._update_history_actions()
        self.status.showMessage(f"{len(entries)} 件を読み込みました", 4000)
        self._apply_simple_view_mode(self._simple_view_enabled)
        self._update_safety_status()
        self._refresh_preview()

    def _handle_table_click(self, index: QModelIndex):
        if index.column() != 0:
            return
        source_index = self.proxy.mapToSource(index)
        entry = self.model.entry_at(source_index.row())
        if not entry:
            return
        if entry.read_only:
            QMessageBox.information(self, "情報", "この項目は参照のみです。")
            return
        desired_state = not entry.enabled
        self._toggle_entry(entry, desired_state, record_history=True)

    def _handle_row_double_click(self, index: QModelIndex):
        if not index or not index.isValid():
            return
        source_index = self.proxy.mapToSource(index)
        entry = self.model.entry_at(source_index.row())
        if not entry:
            return
        self._show_handler_properties(entry)

    def _on_simple_view_toggled(self, enabled: bool):
        self._simple_view_enabled = enabled
        if hasattr(self.settings, "set_simple_view_enabled"):
            self.settings.set_simple_view_enabled(enabled)
        self._apply_simple_view_mode(enabled)

    def _apply_simple_view_mode(self, enabled: bool):
        visible_columns = {
            HandlerTableModel.NAME_COLUMN,
            HandlerTableModel.STATUS_COLUMN,
            HandlerTableModel.SCOPE_COLUMN,
        }
        total_columns = self.model.columnCount()
        for col in range(total_columns):
            hide = enabled and col not in visible_columns
            self.table.setColumnHidden(col, hide)

    def _update_safety_status(self):
        if not hasattr(self, "_safety_label"):
            return
        messages = [
            "書き込み先: HKCU のみ",
            "自動バックアップ: 有効 (.reg 出力)",
            "監査ログ: 有効",
        ]
        self._safety_label.setText(" | ".join(messages))

    def maybe_show_onboarding(self):
        if self._settings_storage.value("onboarding/shown", False, type=bool):
            return
        dialog = TutorialDialog(self)
        dialog.exec()
        self._settings_storage.setValue("onboarding/shown", dialog.dont_show_again())

    def _toggle_selected_entry(self):
        entry = self._selected_entry()
        if not entry:
            return
        if entry.read_only:
            QMessageBox.information(self, "情報", "この項目は参照のみです。")
            return
        self._toggle_entry(entry, not entry.enabled, record_history=True)

    def _open_selected_registry(self):
        entry = self._selected_entry()
        if not entry:
            return
        self._open_registry_entry(entry)

    def _selected_entry(self) -> Optional[HandlerEntry]:
        selection = self.table.selectionModel()
        if not selection or not selection.selectedRows():
            return None
        index = selection.selectedRows()[0]
        return self.model.entry_at(self.proxy.mapToSource(index).row())

    def _create_preview_panel(self):
        self.preview_panel = QWidget()
        preview_layout = QVBoxLayout(self.preview_panel)
        preview_layout.setContentsMargins(8, 8, 8, 8)
        preview_layout.setSpacing(6)
        self.preview_header = QLabel("プレビュー")
        preview_layout.addWidget(self.preview_header)
        self.preview_items_widget = QWidget()
        self.preview_items_layout = QVBoxLayout(self.preview_items_widget)
        self.preview_items_layout.setContentsMargins(0, 0, 0, 0)
        self.preview_items_layout.setSpacing(4)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.preview_items_widget)
        preview_layout.addWidget(scroll)
        self._preview_widgets: Dict[str, QWidget] = {}
        self._current_preview_selection = None

    def _refresh_preview(self):
        if not hasattr(self, "preview_items_layout"):
            return
        self._clear_preview_items()
        self.preview_header.setText(self._preview_header_text())
        for row in range(self.proxy.rowCount()):
            entry = self._entry_from_proxy_row(row)
            if not entry:
                continue
            widget = self._create_preview_widget(entry)
            self.preview_items_layout.addWidget(widget)
            self._preview_widgets[entry.registry_path] = widget
        self.preview_items_layout.addStretch()
        self._update_preview_selection_highlight()

    def _clear_preview_items(self):
        while self.preview_items_layout.count():
            item = self.preview_items_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        self._preview_widgets.clear()

    def _create_preview_widget(self, entry: HandlerEntry) -> QWidget:
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setFrameShadow(QFrame.Raised)
        frame.setProperty("registryPath", entry.registry_path)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(8)
        icon_label = QLabel()
        icon_label.setFixedSize(20, 20)
        if entry.icon:
            icon_label.setPixmap(entry.icon.pixmap(20, 20))
        layout.addWidget(icon_label, alignment=Qt.AlignVCenter)
        name_label = QLabel(entry.name)
        name_label.setStyleSheet(f"color: {self._preview_text_color(entry)};")
        layout.addWidget(name_label, alignment=Qt.AlignVCenter)
        return frame

    def _update_preview_selection_highlight(self):
        selected_path = self._current_preview_selection
        for path, widget in self._preview_widgets.items():
            if path == selected_path:
                widget.setStyleSheet("background-color: #3c7ae5; color: white; border-radius: 4px;")
            else:
                widget.setStyleSheet("background-color: transparent;")

    def _entry_from_proxy_row(self, row: int) -> Optional[HandlerEntry]:
        index = self.proxy.index(row, HandlerTableModel.NAME_COLUMN)
        if not index.isValid():
            return None
        source_index = self.proxy.mapToSource(index)
        return self.model.entry_at(source_index.row())

    def _preview_header_text(self) -> str:
        scope = self.scope_combo.currentText() or "すべて"
        scope_map = {
            "Directory Background": "背景",
            "Folder": "フォルダー",
            "Drive": "ドライブ",
            "*": "すべて",
        }
        scope_text = scope_map.get(scope, scope)
        if self.shellex_filter_action.isChecked():
            type_text = "拡張ハンドラー"
        elif self.shell_filter_action.isChecked():
            type_text = "メインメニュー"
        else:
            type_text = "すべて"
        return f"プレビュー（スコープ: {scope_text}、種別: {type_text}）"

    def _preview_text_color(self, entry: HandlerEntry) -> str:
        if entry.is_broken:
            return "#ff6b6b"
        if not entry.enabled:
            return "#888888"
        return "#f0f0f0"

    def _on_broken_filter_toggled(self, checked: bool):
        self.proxy.set_broken_only(checked)
        self._refresh_preview()

    def _on_table_selection_changed(self, *_args):
        entry = self._selected_entry()
        self._current_preview_selection = entry.registry_path if entry else None
        self._update_preview_selection_highlight()


    def _show_context_menu(self, pos):
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        entry = self.model.entry_at(self.proxy.mapToSource(index).row())
        if not entry:
            return
        menu = self._create_context_menu(entry)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _show_handler_properties(self, entry: HandlerEntry):
        dialog = HandlerPropertiesDialog(
            entry=entry,
            registry=self.registry,
            parent=self,
            toggle_callback=self._toggle_entry,
            on_updated=self.refresh_entries,
        )
        dialog.exec()

    def _create_context_menu(self, entry: HandlerEntry) -> QMenu:
        menu = QMenu(self)
        fav_text = "★に追加" if not entry.is_favorite else "★を解除"
        fav_action = menu.addAction(fav_text)
        fav_action.setObjectName("context_toggle_favorite")
        fav_action.setData("context_toggle_favorite")
        fav_action.triggered.connect(lambda _, e=entry: self._toggle_favorite_entry(e))
        properties_action = menu.addAction("詳細(&P)･･･")
        properties_action.setObjectName("context_properties")
        properties_action.triggered.connect(lambda _, e=entry: self._show_handler_properties(e))
        menu.addSeparator()
        edit_action = menu.addAction("編集…")
        edit_action.setObjectName("context_edit")
        edit_action.setData("context_edit")
        edit_action.setEnabled(not entry.read_only)
        edit_action.triggered.connect(lambda _, e=entry: self._toggle_entry(e, not e.enabled, record_history=True))

        open_target_action = menu.addAction("実体フォルダを開く")
        open_target_action.setObjectName("context_open_target")
        open_target_action.setData("context_open_target")
        open_target_action.setEnabled(self._resolve_target_file(entry) is not None)
        open_target_action.triggered.connect(lambda _, e=entry: self._open_target_location(e))

        open_action = menu.addAction("レジストリを開く")
        open_action.setObjectName("context_open_registry")
        open_action.setData("context_open_registry")
        open_action.triggered.connect(lambda _, e=entry: self._open_registry_entry(e))

        clsid_path = self.registry.clsid_registry_path(entry)
        if clsid_path:
            clsid_action = menu.addAction("CLSIDをレジストリで開く")
            clsid_action.setObjectName("context_open_clsid")
            clsid_action.setData("context_open_clsid")
            clsid_action.triggered.connect(lambda _, path=clsid_path: self._open_registry_key(path))
        return menu

    def _toggle_entry(self, entry: HandlerEntry, desired_state: bool, record_history: bool):
        entry_copy = replace(entry)

        audit_meta = [
            {
                "action": "enable" if desired_state else "disable",
                "item_name": entry.name,
                "scope": entry.scope,
            }
        ]

        def worker():
            before = entry_copy.enabled
            self.registry.toggle_handler(entry_copy, desired_state)
            return {
                "from": before,
                "to": desired_state,
                "entry": entry_copy,
            }

        def after(result: dict):
            updated_entry: HandlerEntry = result["entry"]
            if record_history:
                self.history.record(
                    name=entry.name,
                    registry_path=updated_entry.registry_path,
                    key_name=entry.key_name,
                    base_path=entry.base_path,
                    scope=entry.scope,
                    from_enabled=result["from"],
                    to_enabled=result["to"],
                )
            self.refresh_entries()
            self._update_history_actions()
            state_text = "有効化" if desired_state else "無効化"
            self.status.showMessage(f"{entry.name} を{state_text}しました", 5000)

        self._run_in_background("ハンドラーを更新中...", worker, after, audit_records=audit_meta)

    # ------------------------------------------------------------------ #
    # Backup / Restore / CSV
    # ------------------------------------------------------------------ #
    def _gather_selected_entries(self) -> List[HandlerEntry]:
        selection = self.table.selectionModel()
        entries: List[HandlerEntry] = []
        if not selection:
            return entries
        for proxy_index in selection.selectedRows():
            entry = self.model.entry_at(self.proxy.mapToSource(proxy_index).row())
            if entry:
                entries.append(entry)
        return entries

    def backup_entries(self):
        selected = self._gather_selected_entries()
        selected = [entry for entry in selected if not entry.read_only]
        if not selected:
            selected = [entry for entry in self.model.entries() if not entry.read_only]
        if not selected:
            QMessageBox.information(self, "情報", "バックアップ対象がありません。")
            return
        file_name, _ = QFileDialog.getSaveFileName(self, ".reg を保存", "", "Registry (*.reg)")
        if not file_name:
            return

        def worker():
            count = self.registry.export_to_reg(selected, Path(file_name))
            return count

        def after(count: int):
            QMessageBox.information(self, "完了", f"{count} 件を書き出しました。")

        audit_meta = [
            {
                "action": "backup",
                "item_name": Path(file_name).name,
                "scope": "-",
            }
        ]

        self._run_in_background("バックアップ中...", worker, after, audit_records=audit_meta)

    def restore_from_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, ".reg を選択", "", "Registry (*.reg)")
        if not file_name:
            return

        def worker():
            return self.registry.restore_from_reg(Path(file_name))

        def after(summary: Dict[str, int]):
            message = f"成功: {summary['success']} / 失敗: {summary['failed']} / スキップ: {summary['skipped']}"
            QMessageBox.information(self, "復元結果", message)
            self.refresh_entries()

        audit_meta = [
            {
                "action": "restore",
                "item_name": Path(file_name).name,
                "scope": "-",
            }
        ]

        self._run_in_background("復元中...", worker, after, audit_records=audit_meta)

    def export_csv(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "CSV出力", "", "CSV (*.csv)")
        if not file_name:
            return
        entries = self.model.entries()

        def worker():
            return self.registry.export_to_csv(entries, Path(file_name))

        def after(count: int):
            QMessageBox.information(self, "CSV出力", f"{count} 件を書き出しました。")

        audit_meta = [
            {
                "action": "csv_export",
                "item_name": Path(file_name).name,
                "scope": "-",
            }
        ]

        self._run_in_background("CSV出力中...", worker, after, audit_records=audit_meta)

    # ------------------------------------------------------------------ #
    # Presets
    # ------------------------------------------------------------------ #
    def apply_preset(self, preset: Preset):
        current_entries = self.model.entries()
        plan = preset.planned_changes(current_entries)
        targets = [
            (entry, plan[entry.registry_path])
            for entry in current_entries
            if entry.registry_path in plan and not entry.read_only
        ]
        changes = [
            (entry, desired_state)
            for entry, desired_state in targets
            if entry.enabled != desired_state
        ]
        if not changes:
            QMessageBox.information(self, "プリセット", "適用対象がありません。")
            return
        preview_rows = [
            PlannedChange(name=entry.name, scope=entry.scope, before=entry.enabled, after=desired)
            for entry, desired in changes
        ]
        preview_dialog = PresetPreviewDialog(preset.label, preview_rows, self)
        if preview_dialog.exec() != QDialog.Accepted:
            return

        def worker():
            results = []
            for entry, desired in changes:
                entry_copy = replace(entry)
                before = entry_copy.enabled
                self.registry.toggle_handler(entry_copy, desired)
                results.append((entry, entry_copy, before, desired))
            return results

        def after(results: List[tuple]):
            for original, updated, before, after_state in results:
                self.history.record(
                    name=original.name,
                    registry_path=updated.registry_path,
                    key_name=original.key_name,
                    base_path=original.base_path,
                    scope=original.scope,
                    from_enabled=before,
                    to_enabled=after_state,
                )
            self.refresh_entries()
            QMessageBox.information(self, "プリセット", f"{len(results)} 件を更新しました。")

        audit_meta = [
            {
                "action": "preset",
                "item_name": f"{entry.name} ({'有効化' if desired else '無効化'})",
                "scope": entry.scope,
            }
            for entry, desired in changes
        ]

        self._run_in_background(f"{preset.label} を適用中...", worker, after, audit_records=audit_meta)

    # ------------------------------------------------------------------ #
    # Undo / Redo
    # ------------------------------------------------------------------ #
    def undo_last_action(self):
        entry = self.history.undo()
        if not entry:
            return
        self._apply_history_entry(entry, current_state=entry.to_enabled, target_state=entry.from_enabled)

    def redo_last_action(self):
        entry = self.history.redo()
        if not entry:
            return
        self._apply_history_entry(entry, current_state=entry.from_enabled, target_state=entry.to_enabled)

    def _apply_history_entry(self, entry: HistoryEntry, *, current_state: bool, target_state: bool):
        audit_meta = [
            {
                "action": "enable" if target_state else "disable",
                "item_name": entry.name,
                "scope": entry.scope,
            }
        ]

        def worker():
            temp = HandlerEntry(
                name=entry.name,
                key_name=entry.key_name,
                scope=entry.scope,
                registry_path=self._path_for_state(entry.base_path, entry.key_name, current_state),
                base_path=entry.base_path,
                enabled=current_state,
                last_modified=None,
                status="",
                read_only=False,
            )
            self.registry.toggle_handler(temp, target_state)
            return True

        def after(_result: bool):
            self.refresh_entries()
            action = "元に戻しました" if target_state else "再適用しました"
            self.status.showMessage(f"履歴操作: {entry.name} を{action}", 4000)
            self._update_history_actions()

        self._run_in_background("履歴を適用中...", worker, after, audit_records=audit_meta)

    def _path_for_state(self, base_path: str, key_name: str, enabled: bool) -> str:
        if enabled:
            return f"{base_path}\\{key_name}"
        return f"{base_path}\\DisabledHandlers\\{key_name}"

    def _update_history_actions(self):
        self.undo_action.setEnabled(self.history.can_undo())
        self.redo_action.setEnabled(self.history.can_redo())

    # ------------------------------------------------------------------ #
    # Misc
    # ------------------------------------------------------------------ #
    def restart_explorer(self):
        self.registry.restart_explorer()
        QMessageBox.information(self, "Explorer", "Explorer を再起動しました。")

    def _open_registry_entry(self, entry: HandlerEntry):
        key_path = f"HKEY_CLASSES_ROOT\\{entry.registry_path}"
        self._open_registry_key(key_path)

    def _open_registry_key(self, key_path: str):
        clipboard = QApplication.clipboard()
        clipboard.setText(key_path)
        try:
            subprocess.Popen(["regedit.exe", "/m", key_path])
        except Exception as exc:
            self.logger.debug("Failed to open regedit for %s: %s", key_path, exc)
            QMessageBox.information(self, "レジストリ", f"キーをクリップボードにコピーしました。\n{key_path}")
        else:
            QMessageBox.information(
                self,
                "レジストリ",
                f"regedit を開きました。キーはクリップボードにコピー済みです。\n{key_path}",
            )

    def _resolve_target_file(self, entry: HandlerEntry) -> Optional[str]:
        path = entry.target_path
        if not path:
            return None
        candidate = path.strip().strip('"')
        if not os.path.exists(candidate):
            candidate = candidate.split(" ")[0].strip('"')
        if os.path.exists(candidate):
            return candidate
        return None

    def _open_target_location(self, entry: HandlerEntry):
        file_path = self._resolve_target_file(entry)
        if not file_path:
            QMessageBox.warning(self, "実体を開く", "パスを特定できませんでした。")
            return
        try:
            subprocess.Popen(["explorer.exe", "/select,", file_path])
        except Exception as exc:
            self.logger.error("Failed to open explorer for %s: %s", file_path, exc)
            QMessageBox.warning(self, "実体を開く", f"フォルダを開けませんでした: {exc}")

    def open_audit_folder(self):
        try:
            self.audit_path.mkdir(parents=True, exist_ok=True)
            if sys.platform.startswith("win"):
                os.startfile(self.audit_path)  # type: ignore[arg-type]
            elif sys.platform.startswith("darwin"):
                subprocess.run(["open", str(self.audit_path)], check=False)
            else:
                subprocess.run(["xdg-open", str(self.audit_path)], check=False)
        except Exception as exc:
            self.logger.error("Failed to open audit folder: %s", exc)
            QMessageBox.warning(self, "監査ログ", f"フォルダを開けませんでした: {exc}")

    def toggle_theme(self, checked: bool):
        self.current_theme = "dark" if checked else "light"
        qdarktheme.setup_theme(self.current_theme)

    def closeEvent(self, event):
        try:
            self.history.save_snapshot(self.history_path)
        except Exception as exc:  # pragma: no cover - best effort
            self.logger.error("Failed to persist history: %s", exc)
        self._executor.shutdown(wait=False)
        super().closeEvent(event)

    # ------------------------------------------------------------------ #
    # Background helpers
    # ------------------------------------------------------------------ #
    def _run_in_background(
        self,
        description: str,
        func: Callable[[], object],
        on_success: Optional[Callable[[object], None]] = None,
        audit_records: Optional[List[Dict[str, str]]] = None,
    ):
        dialog = QProgressDialog(description, "", 0, 0, self)
        dialog.setCancelButton(None)
        dialog.setWindowModality(Qt.ApplicationModal)
        dialog.show()

        def task_wrapper():
            try:
                result = func()
                return {"ok": True, "result": result}
            except Exception as exc:  # pragma: no cover - UI feedback path
                self.logger.exception("Background task failed: %s", description)
                return {"ok": False, "error": str(exc)}

        if _HAS_QTCONCURRENT:
            future = QtConcurrent.run(task_wrapper)

            def is_finished():
                return future.isFinished()

            def get_result():
                return future.result()

        else:
            future = self._executor.submit(task_wrapper)

            def is_finished():
                return future.done()

            def get_result():
                return future.result()
        timer = QTimer(self)
        timer.setInterval(50)
        self._pending_timers.append(timer)

        def _finalize(payload):
            if timer in self._pending_timers:
                self._pending_timers.remove(timer)
            timer.stop()
            timer.deleteLater()
            dialog.close()
            if not payload["ok"]:
                QMessageBox.critical(self, "エラー", payload["error"])
                self._append_audit_records(audit_records, "fail", payload["error"])
                return
            self._append_audit_records(audit_records, "ok", "")
            if on_success:
                on_success(payload["result"])

        def _poll_future():
            if not is_finished():
                return
            payload = get_result()
            _finalize(payload)

        timer.timeout.connect(_poll_future)
        timer.start()

    def _append_audit_records(
        self,
        records: Optional[List[Dict[str, str]]],
        result: str,
        error: str,
    ):
        if not self.audit_logger or not records:
            return
        for record in records:
            try:
                self.audit_logger.log(
                    action=record.get("action", ""),
                    item_name=record.get("item_name", ""),
                    scope=record.get("scope", ""),
                    result=result,
                    error=error,
                )
            except Exception as exc:  # pragma: no cover
                self.logger.warning("Failed to append audit entry: %s", exc)


class PresetPreviewDialog(QDialog):
    """Dialog that previews preset changes with color-coded rows."""

    def __init__(self, preset_label: str, changes: List[PlannedChange], parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle(f"プリセット適用: {preset_label}")
        self.resize(620, 420)

        layout = QVBoxLayout(self)
        enable_count = sum(1 for change in changes if change.after and not change.before)
        disable_count = sum(1 for change in changes if change.before and not change.after)
        summary = QLabel(f"有効化 {enable_count} 件 / 無効化 {disable_count} 件", self)
        layout.addWidget(summary)

        table = QTableWidget(len(changes), 4, self)
        table.setHorizontalHeaderLabels(["名前", "スコープ", "現在", "適用後"])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.NoEditTriggers)

        for row, change in enumerate(changes):
            before_text = "有効" if change.before else "無効"
            after_text = "有効" if change.after else "無効"
            items = [
                QTableWidgetItem(change.name),
                QTableWidgetItem(change.scope),
                QTableWidgetItem(before_text),
                QTableWidgetItem(after_text),
            ]
            color = None
            if change.after and not change.before:
                color = QColor("#1E88E5")
            elif change.before and not change.after:
                color = QColor("#E53935")
            for column, item in enumerate(items):
                alignment = Qt.AlignCenter if column >= 2 else Qt.AlignLeft | Qt.AlignVCenter
                item.setTextAlignment(alignment)
                if color:
                    item.setBackground(color)
                    item.setForeground(Qt.white)
                table.setItem(row, column, item)

        table.resizeColumnsToContents()
        layout.addWidget(table)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, parent=self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class DuplicateDialog(QDialog):
    def __init__(self, groups: List[DuplicateGroup], registry: RegistryManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("重複検出")
        self.resize(900, 600)
        self.registry = registry
        self.groups = groups
        self.selection: Dict[int, int] = {
            idx: group.suggested_keep_index for idx, group in enumerate(groups)
        }

        layout = QVBoxLayout(self)
        self.tree = QTreeWidget(self)
        self.tree.setColumnCount(6)
        self.tree.setHeaderLabels(["保持", "名前", "種別", "スコープ", "コマンド/CLSID", "最終更新"])
        self.tree.itemClicked.connect(self._on_item_clicked)
        layout.addWidget(self.tree)

        self._populate_tree()

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.cancel_btn = QPushButton("キャンセル", self)
        self.cancel_btn.clicked.connect(self.reject)
        self.ok_btn = QPushButton("隔離を実行", self)
        self.ok_btn.clicked.connect(self.accept)
        btn_layout.addWidget(self.cancel_btn)
        btn_layout.addWidget(self.ok_btn)
        layout.addLayout(btn_layout)

    def _populate_tree(self):
        self.tree.clear()
        for idx, group in enumerate(self.groups):
            group_item = QTreeWidgetItem(self.tree)
            group_item.setFirstColumnSpanned(True)
            group_item.setText(0, f"{group.reason.upper()} - {group.key}")
            group_item.setExpanded(True)
            for entry_index, entry in enumerate(group.entries):
                child = QTreeWidgetItem(group_item)
                child.setText(1, entry.name)
                child.setText(2, entry.type)
                child.setText(3, entry.scope)
                child.setText(4, entry.command or entry.clsid or "")
                lw = entry.last_write_time.strftime("%Y-%m-%d %H:%M:%S") if entry.last_write_time else ""
                child.setText(5, lw)
                keeps = self.selection[idx] == entry_index
                child.setText(0, "保持" if keeps else "隔離")
                child.setData(0, Qt.UserRole, (idx, entry_index))

    def _on_item_clicked(self, item: QTreeWidgetItem, column: int):
        data = item.data(0, Qt.UserRole)
        if not data:
            return
        group_idx, entry_idx = data
        if self.selection.get(group_idx) == entry_idx:
            return
        self.selection[group_idx] = entry_idx
        start = self.tree.topLevelItem(group_idx)
        if not start:
            return
        for child_idx in range(start.childCount()):
            child = start.child(child_idx)
            child.setText(0, "保持" if child_idx == entry_idx else "隔離")

    def run_quarantine_with_backup(self) -> Tuple[int, List[str]]:
        to_quarantine = []
        for group_idx, group in enumerate(self.groups):
            keep_idx = self.selection.get(group_idx, group.suggested_keep_index)
            for idx, entry in enumerate(group.entries):
                if idx != keep_idx:
                    to_quarantine.append(entry)
        if not to_quarantine:
            return 0, []
        backup_path = self._backup_path()
        self.registry.export_to_reg(to_quarantine, backup_path)
        quarantined = 0
        errors = []
        for entry in to_quarantine:
            try:
                self.registry.quarantine_key(entry)
                quarantined += 1
            except Exception as exc:
                errors.append(f"{entry.name}: {exc}")
        return quarantined, errors

    def _backup_path(self) -> Path:
        logs_dir = Path(__file__).resolve().parent.parent / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        return logs_dir / f"duplicates_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.reg"


class HandlerPropertiesDialog(QDialog):
    def __init__(
        self,
        entry: HandlerEntry,
        registry: RegistryManager,
        toggle_callback: Callable[[HandlerEntry, bool, bool], None],
        on_updated: Callable[[], None],
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.entry = entry
        self.registry = registry
        self.toggle_callback = toggle_callback
        self.on_updated = on_updated
        self.setWindowTitle(f"詳細: {entry.name}")
        self.resize(580, 360)

        form = QFormLayout()
        self.name_edit = QLineEdit(entry.name)
        form.addRow("表示名", self.name_edit)
        self.type_label = QLabel("ShellEx" if entry.type == "shellex" else "shell/verb")
        form.addRow("種別", self.type_label)
        self.scope_label = QLabel(entry.scope)
        form.addRow("スコープ", self.scope_label)

        command_widget = QWidget()
        command_layout = QHBoxLayout(command_widget)
        command_layout.setContentsMargins(0, 0, 0, 0)
        self.command_edit = QLineEdit(entry.command or entry.clsid or "")
        self.command_edit.setReadOnly(entry.type != "verb")
        command_layout.addWidget(self.command_edit)
        self.command_widget = command_widget
        form.addRow("コマンド / CLSID", command_widget)

        path_widget = QWidget()
        path_layout = QHBoxLayout(path_widget)
        path_layout.setContentsMargins(0, 0, 0, 0)
        self.registry_path_edit = QLineEdit(entry.full_key_path)
        self.registry_path_edit.setReadOnly(True)
        path_layout.addWidget(self.registry_path_edit)
        copy_button = QPushButton("コピー")
        copy_button.clicked.connect(self._copy_registry_path)
        path_layout.addWidget(copy_button)
        form.addRow("レジストリパス", path_widget)

        icon_layout = QHBoxLayout()
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(64, 64)
        self.icon_label.setAlignment(Qt.AlignCenter)
        icon_layout.addWidget(self.icon_label)
        form.addRow("アイコン", icon_layout)
        self._update_icon_preview()

        self.broken_label = QLabel(entry.broken_reason or "正常")
        form.addRow("状態", self.broken_label)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        test_btn = QPushButton("テスト実行")
        test_btn.clicked.connect(self._test_command)
        btn_layout.addWidget(test_btn)
        repair_btn = QPushButton("修復...")
        repair_btn.clicked.connect(self._repair_command)
        btn_layout.addWidget(repair_btn)
        self.disable_btn = QPushButton("無効化" if entry.enabled else "有効化")
        self.disable_btn.clicked.connect(self._toggle_entry_state)
        btn_layout.addWidget(self.disable_btn)
        close_btn = QPushButton("閉じる")
        close_btn.clicked.connect(self.close)
        btn_layout.addWidget(close_btn)

        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.addLayout(form)
        layout.addLayout(btn_layout)
        layout.setContentsMargins(12, 12, 12, 12)
        self.setLayout(layout)

    def _update_icon_preview(self):
        if self.entry.icon and not self.entry.icon.isNull():
            pixmap = self.entry.icon.pixmap(64, 64)
            self.icon_label.setPixmap(pixmap)
        else:
            self.icon_label.setText("アイコンなし")

    def _copy_registry_path(self):
        QApplication.clipboard().setText(self.entry.full_key_path)
        QMessageBox.information(self, "コピー完了", "レジストリパスをコピーしました。")

    def _test_command(self):
        command = self.command_edit.text().strip()
        exe = self.registry.resolve_command_executable(command)
        if not exe:
            QMessageBox.warning(self, "テスト実行", "実行コマンドが設定されていません。")
            return
        if not Path(exe).exists():
            QMessageBox.warning(self, "テスト実行", f"{exe} が存在しません。")
            return
        try:
            subprocess.Popen([exe], cwd=os.path.dirname(exe) or None)
            QMessageBox.information(self, "テスト実行", "アプリケーションを起動しました。")
        except Exception as exc:
            QMessageBox.warning(self, "テスト実行", f"起動に失敗しました: {exc}")

    def _repair_command(self):
        if self.entry.read_only:
            QMessageBox.warning(self, "修復", "読み取り専用のエントリは修復できません。")
            return
        exe_path, _ = QFileDialog.getOpenFileName(
            self, "実行ファイルを選択", "", "実行ファイル (*.exe)"
        )
        if not exe_path:
            return
        command = f"\"{exe_path}\" \"%1\""
        try:
            export_to_reg([self.entry.full_key_path])
            name = self.name_edit.text().strip()
            if name:
                self.registry.update_display_name(self.entry, name)
            self.registry.update_command(self.entry, command)
            new_icon = self.registry._icon_from_file(exe_path)
            if new_icon:
                self.entry.icon = new_icon
        except Exception as exc:
            QMessageBox.critical(self, "修復", f"書き換えに失敗しました: {exc}")
            return
        self.command_edit.setText(command)
        self._update_icon_preview()
        self._refresh_broken_state()
        QMessageBox.information(self, "修復", "コマンドを書き換えました。")
        self.on_updated()

    def _toggle_entry_state(self):
        if self.entry.read_only:
            QMessageBox.warning(self, "状態変更", "読み取り専用のエントリは変更できません。")
            return
        desired = not self.entry.enabled
        self.toggle_callback(self.entry, desired, True)
        self.on_updated()
        self.close()

    def _refresh_broken_state(self):
        broken, reason = self.registry._evaluate_handler_integrity(
            self.entry, self.entry.type
        )
        self.entry.is_broken = broken
        self.entry.broken_reason = reason
        self.broken_label.setText(reason or "正常")


class NewHandlerDialog(QDialog):
    SCOPE_CHOICES = [
        ("*", "すべて"),
        ("Folder", "フォルダ"),
        ("Directory Background", "ディレクトリ背景"),
        ("Drive", "ドライブ"),
    ]

    def __init__(
        self,
        *,
        registry: RegistryManager,
        on_created: Callable[[], None],
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.registry = registry
        self.on_created = on_created
        self.setWindowTitle("新規メニュー追加")
        self.resize(520, 240)

        form = QFormLayout()
        self.name_edit = QLineEdit()
        form.addRow("表示名", self.name_edit)

        self.scope_combo = QComboBox()
        for key, label in self.SCOPE_CHOICES:
            self.scope_combo.addItem(label, key)
        form.addRow("スコープ", self.scope_combo)

        exe_widget = QWidget()
        exe_layout = QHBoxLayout(exe_widget)
        exe_layout.setContentsMargins(0, 0, 0, 0)
        self.exe_edit = QLineEdit()
        exe_layout.addWidget(self.exe_edit)
        browse_btn = QPushButton("参照")
        browse_btn.clicked.connect(self._choose_executable)
        exe_layout.addWidget(browse_btn)
        form.addRow("実行ファイル", exe_widget)

        buttons = QHBoxLayout()
        buttons.addStretch()
        create_btn = QPushButton("追加")
        create_btn.clicked.connect(self._on_create)
        buttons.addWidget(create_btn)
        cancel_btn = QPushButton("キャンセル")
        cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(cancel_btn)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(buttons)

    def _choose_executable(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "実行ファイルを選択", "", "実行ファイル (*.exe)"
        )
        if file_name:
            self.exe_edit.setText(file_name)

    def _on_create(self):
        display = self.name_edit.text().strip()
        exe_path = self.exe_edit.text().strip()
        scope = self.scope_combo.currentData()
        if not display or not exe_path:
            QMessageBox.warning(self, "入力不足", "表示名と実行ファイルは必須です。")
            return
        try:
            handler_path = self.registry.create_custom_handler(display, scope, exe_path)
        except Exception as exc:
            QMessageBox.critical(self, "新規メニュー追加", f"作成に失敗しました: {exc}")
            return
        QMessageBox.information(
            self,
            "新規メニュー追加",
            f"{display} を {handler_path} に作成しました。HKCU のキーをご確認ください。",
        )
        self.on_created()
        super().accept()


class TutorialDialog(QDialog):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Light Context Menu 入門")
        self.resize(420, 240)
        layout = QVBoxLayout(self)
        intro = QLabel("Light Context Menu Manager の基本操作を紹介します。")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        steps = QLabel(
            "1. チェックボックスで有効/無効を切り替え、必要な項目だけ残せます。\n"
            "2. 「壊れている項目のみ」ボタンで問題のあるメニューを絞り込めます。\n"
            "3. 「新規メニュー追加(N)…」でお気に入りアプリを追加し、自分だけのメニューを作成できます。"
        )
        steps.setWordWrap(True)
        layout.addWidget(steps)
        self.checkbox = QCheckBox("二度と表示しない")
        self.checkbox.setChecked(True)
        layout.addWidget(self.checkbox)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok, parent=self)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def dont_show_again(self) -> bool:
        return bool(self.checkbox.isChecked())
