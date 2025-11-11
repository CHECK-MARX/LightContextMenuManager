from __future__ import annotations

import ctypes
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox

from .audit import AuditLogger
from .history import HistoryManager
from .presets import PresetManager
from .registry import RegistryManager
from .settings import SettingsManager
from .views.main_window import MainWindow


def ensure_admin():
    """Restart the script with elevated privileges if needed."""
    if os.name != "nt":
        return
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        return
    if not is_admin:
        params = " ".join(f'"{arg}"' for arg in sys.argv)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        sys.exit(0)


def configure_logging(log_path: Path) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    return root


def main():
    ensure_admin()
    base_dir = Path(__file__).resolve().parent.parent
    logs_dir = base_dir / "logs"
    presets_dir = base_dir / "presets"
    logger = configure_logging(logs_dir / "app.log")

    history_path = logs_dir / "history_snapshot.json"
    history = HistoryManager()
    history.load_snapshot(history_path)

    registry = RegistryManager(logger=logger)
    presets = PresetManager(presets_dir)
    settings = SettingsManager(base_dir / "settings.json", logger=logger)
    audit_logger = AuditLogger(base_dir / "audit", enabled=settings.audit_enabled(), logger=logger)

    app = QApplication(sys.argv)
    try:
        window = MainWindow(
            registry=registry,
            history=history,
            history_path=history_path,
            presets=presets,
             audit_logger=audit_logger,
             audit_path=base_dir / "audit",
            logger=logger,
        )
        window.show()
    except Exception:
        logger.exception("Failed to start UI")
        QMessageBox.critical(None, "致命的なエラー", "アプリケーションを起動できませんでした。ログを確認してください。")
        return
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
