from __future__ import annotations

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication


def setup_theme(theme_name: str = "dark"):
    """Minimal qdarktheme-compatible API with a Fusion palette."""

    app = QApplication.instance()
    if app is None:
        return

    if theme_name.lower() == "dark":
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor("#202124"))
        palette.setColor(QPalette.WindowText, QColor("#FFFFFF"))
        palette.setColor(QPalette.Base, QColor("#121212"))
        palette.setColor(QPalette.AlternateBase, QColor("#1E1E1E"))
        palette.setColor(QPalette.ToolTipBase, QColor("#FFFFFF"))
        palette.setColor(QPalette.ToolTipText, QColor("#000000"))
        palette.setColor(QPalette.Text, QColor("#FFFFFF"))
        palette.setColor(QPalette.Button, QColor("#2D2E30"))
        palette.setColor(QPalette.ButtonText, QColor("#FFFFFF"))
        palette.setColor(QPalette.BrightText, QColor("#FF5252"))
        palette.setColor(QPalette.Highlight, QColor("#3D6DEB"))
        palette.setColor(QPalette.HighlightedText, QColor("#FFFFFF"))
        app.setStyle("Fusion")
        app.setPalette(palette)
    else:
        app.setPalette(app.style().standardPalette())
