"""Display a real Windows Shell context menu without executing a command."""

from __future__ import annotations

from pathlib import Path
from typing import Optional


class NativeMenuUnavailable(RuntimeError):
    """Raised when the Windows Shell integration is not available."""


def show_context_menu(path: str, hwnd: int, x: int, y: int) -> Optional[int]:
    """Show the native context menu for *path* without invoking commands."""
    if not Path(path).exists():
        raise FileNotFoundError(path)
    try:
        import pythoncom
        import win32con
        import win32gui
        from win32com.shell import shell
    except ImportError as exc:  # pragma: no cover - Windows dependency
        raise NativeMenuUnavailable(
            "Windows Shell連携に必要なpywin32がインストールされていません。"
        ) from exc

    pythoncom.CoInitialize()
    menu = None
    try:
        pidl, _attributes = shell.SHParseDisplayName(str(Path(path)), 0)
        desktop = shell.SHGetDesktopFolder()
        _result, context_menu = desktop.GetUIObjectOf(hwnd, [pidl], shell.IID_IContextMenu, 0)
        menu = win32gui.CreatePopupMenu()
        context_menu.QueryContextMenu(menu, 0, 1, 0x7FFF, 0x00000000)
        flags = win32con.TPM_RETURNCMD | win32con.TPM_RIGHTBUTTON
        command = win32gui.TrackPopupMenu(menu, flags, x, y, 0, hwnd, None)
        return int(command) if command else None
    finally:
        if menu:
            win32gui.DestroyMenu(menu)
        pythoncom.CoUninitialize()
