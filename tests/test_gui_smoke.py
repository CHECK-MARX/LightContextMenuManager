from __future__ import annotations

from pathlib import Path
from typing import List

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QAction, QIcon, QPixmap
from PySide6.QtWidgets import QMessageBox, QMenu

from src.audit import AuditLogger
from src.history import HistoryManager
from src.models import HandlerEntry
from src.presets import PresetManager
from src.settings import SettingsManager
from src.views.main_window import MainWindow


class DummyRegistry:
    def __init__(self, entries: List[HandlerEntry]):
        self._entries = entries
        self.scan_calls = 0

    def scan_handlers(self) -> List[HandlerEntry]:
        self.scan_calls += 1
        return list(self._entries)

    def toggle_handler(self, entry: HandlerEntry, enable: bool):
        entry.enabled = enable
        entry.status = "有効" if enable else "無効"

    def export_to_csv(self, entries: List[HandlerEntry], destination: Path) -> int:
        Path(destination).write_text("name\n", encoding="utf-8")
        return len(entries)

    def export_to_reg(self, entries, destination: Path) -> int:
        return len(list(entries))

    def restore_from_reg(self, source: Path):
        return {"success": 0, "failed": 0, "skipped": 0}

    def restart_explorer(self):
        return True

    def clsid_registry_path(self, entry: HandlerEntry):
        if entry.clsid:
            return f"HKEY_CLASSES_ROOT\\CLSID\\{entry.clsid}"
        return None

class _DialogStub:
    def __init__(self, *args, **kwargs):
        self.closed = False

    def setCancelButton(self, *_args, **_kwargs):
        pass

    def setWindowModality(self, *_args, **_kwargs):
        pass

    def show(self):
        pass

    def close(self):
        self.closed = True


def _sample_entries() -> List[HandlerEntry]:
    base = r"*\\shellex\\ContextMenuHandlers"
    pixmap = QPixmap(16, 16)
    pixmap.fill(Qt.blue)
    icon = QIcon(pixmap)
    return [
        HandlerEntry(
            name="Alpha Tool",
            type="verb",
            scope="*",
            key_name="Alpha",
            registry_path=f"{base}\\Alpha",
            full_key_path=f"HKEY_CLASSES_ROOT\\{base}\\Alpha",
            base_path=base,
            base_rel_path=base,
            enabled=True,
            last_modified=None,
            last_write_time=None,
            status="有効",
            read_only=False,
            icon=icon,
            tooltip="実体: alpha\nキー: path\n状態: 有効",
            command=r'C:\Windows\explorer.exe "%1"',
            normalized_name="alpha tool",
            normalized_command=r"c:\windows\explorer.exe %1",
            target_path=r"C:\Windows\explorer.exe",
        ),
        HandlerEntry(
            name="Beta Service",
            type="shellex",
            scope="Folder",
            key_name="Beta",
            registry_path=f"{base}\\Beta",
            full_key_path=f"HKEY_CLASSES_ROOT\\{base}\\Beta",
            base_path=base,
            base_rel_path=base,
            enabled=True,
            last_modified=None,
            last_write_time=None,
            status="有効",
            read_only=False,
            icon=icon,
            tooltip="実体: beta\nキー: path\n状態: 有効",
            clsid="{00000000-0000-0000-0000-000000000000}",
        ),
    ]


@pytest.mark.qt
def test_main_window_smoke(qtbot, tmp_path, monkeypatch):
    entries = _sample_entries()
    registry = DummyRegistry(entries)
    history = HistoryManager()
    presets_dir = tmp_path / "presets"
    presets_dir.mkdir()
    preset_file = presets_dir / "dev.json"
    preset_file.write_text(
        '{"id": "dev", "label": "Dev", "description": "", "rules": []}', encoding="utf-8"
    )
    presets = PresetManager(presets_dir)

    monkeypatch.setattr("src.views.main_window.QProgressDialog", _DialogStub)
    monkeypatch.setattr(
        "src.views.main_window.QMessageBox.information", lambda *args, **kwargs: QMessageBox.Ok
    )

    fake_csv = tmp_path / "handlers.csv"

    def _fake_save_dialog(*_args, **_kwargs):
        return str(fake_csv), "csv"

    monkeypatch.setattr("src.views.main_window.QFileDialog.getSaveFileName", _fake_save_dialog)

    audit_dir = tmp_path / "audit"
    audit_logger = AuditLogger(audit_dir, enabled=False)
    settings = SettingsManager(tmp_path / "settings.json")

    window = MainWindow(
        registry=registry,
        history=history,
        history_path=tmp_path / "history.json",
        presets=presets,
        audit_logger=audit_logger,
        audit_path=audit_dir,
        settings=settings,
    )
    qtbot.addWidget(window)

    qtbot.waitUntil(lambda: registry.scan_calls >= 1, timeout=10000)
    qtbot.waitUntil(lambda: window.model.rowCount() == len(entries), timeout=10000)

    window.search_field.setText("Alpha")
    qtbot.waitUntil(lambda: window.proxy.rowCount() == 1)
    assert window.proxy.rowCount() == 1
    window.search_field.clear()
    qtbot.waitUntil(lambda: window.proxy.rowCount() == len(entries))

    def trigger_toolbar(text: str):
        action = next((act for act in window.toolbar.actions() if act.text() == text), None)
        assert action is not None
        action.trigger()

    trigger_toolbar("再読み込み")
    qtbot.waitUntil(lambda: registry.scan_calls >= 2)

    window.undo_action.setEnabled(True)
    window.undo_action.trigger()
    window.redo_action.setEnabled(True)
    window.redo_action.trigger()

    trigger_toolbar("CSV出力")
    qtbot.waitUntil(lambda: fake_csv.exists())

    result_holder = {}

    def _work():
        return "done"

    def _after(value):
        result_holder["value"] = value

    window._run_in_background("test", _work, _after)
    qtbot.waitUntil(lambda: result_holder.get("value") == "done")

    index = window.proxy.index(0, 1)
    assert isinstance(index.data(Qt.DecorationRole), QIcon)
    assert index.data(Qt.ToolTipRole)

    entry = window.model.entry_at(0)
    assert entry is not None
    menu = window._create_context_menu(entry)
    captured_actions = menu.actions()
    assert captured_actions
    assert any(action.data() == "context_open_registry" for action in captured_actions)
    assert any(action.data() == "context_edit" for action in captured_actions)

    window.close()
