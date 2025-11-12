from __future__ import annotations

import csv
import ctypes
import logging
import os
import re
import subprocess
from ctypes import wintypes
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import winreg
from PySide6.QtGui import QIcon, QPixmap

from .models import HandlerEntry

shell32 = ctypes.windll.shell32
user32 = ctypes.windll.user32
shlwapi = ctypes.windll.shlwapi
version = ctypes.windll.version

MAX_PATH = 260
HRESULT = ctypes.c_long


class SHFILEINFO(ctypes.Structure):
    _fields_ = [
        ("hIcon", wintypes.HICON),
        ("iIcon", ctypes.c_int),
        ("dwAttributes", wintypes.DWORD),
        ("szDisplayName", wintypes.WCHAR * MAX_PATH),
        ("szTypeName", wintypes.WCHAR * 80),
    ]


SHGFI_ICON = 0x000000100
SHGFI_SMALLICON = 0x000000001
SHGFI_USEFILEATTRIBUTES = 0x000000010

shlwapi.SHLoadIndirectString.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    wintypes.UINT,
    ctypes.c_void_p,
]
shlwapi.SHLoadIndirectString.restype = HRESULT

HKCR = winreg.HKEY_CLASSES_ROOT
READ_FLAGS = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
WRITE_FLAGS = winreg.KEY_READ | winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY

SHELLEX_TARGETS = [
    {"scope": "*", "path": r"*\shellex\ContextMenuHandlers", "kind": "shellex"},
    {"scope": "Folder", "path": r"Folder\shellex\ContextMenuHandlers", "kind": "shellex"},
    {"scope": "Directory Background", "path": r"Directory\Background\shellex\ContextMenuHandlers", "kind": "shellex"},
    {"scope": "Drive", "path": r"Drive\shellex\ContextMenuHandlers", "kind": "shellex"},
]

SHELL_TARGETS = [
    {"scope": "*", "path": r"*\shell", "kind": "shell"},
    {"scope": "Folder", "path": r"Folder\shell", "kind": "shell"},
]

REG_HEADER = "Windows Registry Editor Version 5.00"


class RegistryOperationError(Exception):
    """Raised when registry manipulation fails."""


class RegistryManager:
    """High-level operations for context menu handlers."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self._icon_cache: Dict[str, QIcon] = {}

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def scan_handlers(self) -> List[HandlerEntry]:
        entries: List[HandlerEntry] = []
        for target in SHELLEX_TARGETS:
            entries.extend(self._read_scope(target, read_only=False))
        for target in SHELL_TARGETS:
            entries.extend(self._read_scope(target, read_only=True))
        return sorted(entries, key=lambda item: (item.scope, item.name.lower()))

    def _read_scope(self, descriptor: dict, read_only: bool) -> List[HandlerEntry]:
        scope = descriptor["scope"]
        base_path = descriptor["path"]
        kind = descriptor.get("kind", "shellex")
        collected: List[HandlerEntry] = []
        collected.extend(
            self._iterate_entries(
                parent_path=base_path,
                base_path=base_path,
                scope=scope,
                enabled=True,
                read_only=read_only,
                handler_kind=kind,
            )
        )
        if not read_only:
            disabled_parent = f"{base_path}\\DisabledHandlers"
            collected.extend(
                self._iterate_entries(
                    parent_path=disabled_parent,
                    base_path=base_path,
                    scope=scope,
                    enabled=False,
                    read_only=False,
                    handler_kind=kind,
                )
            )
        return collected

    def _iterate_entries(
        self,
        *,
        parent_path: str,
        base_path: str,
        scope: str,
        enabled: bool,
        read_only: bool,
        handler_kind: str,
    ) -> List[HandlerEntry]:
        entries: List[HandlerEntry] = []
        try:
            with winreg.OpenKey(HKCR, parent_path, 0, READ_FLAGS) as parent_key:
                index = 0
                while True:
                    try:
                        key_name = winreg.EnumKey(parent_key, index)
                    except OSError:
                        break
                    index += 1
                    registry_path = f"{parent_path}\\{key_name}"
                    entry = self._build_entry(
                        registry_path=registry_path,
                        base_path=base_path,
                        scope=scope,
                        key_name=key_name,
                        enabled=enabled,
                        read_only=read_only,
                        handler_kind=handler_kind,
                    )
                    if entry:
                        entries.append(entry)
        except FileNotFoundError:
            return []
        return entries

    def _build_entry(
        self,
        *,
        registry_path: str,
        base_path: str,
        scope: str,
        key_name: str,
        enabled: bool,
        read_only: bool,
        handler_kind: str,
    ) -> Optional[HandlerEntry]:
        try:
            with winreg.OpenKey(HKCR, registry_path, 0, READ_FLAGS) as key:
                display_name = key_name
                default_value = ""
                clsid_value = None
                try:
                    default_value, _ = winreg.QueryValueEx(key, None)
                    if default_value:
                        display_name = str(default_value)
                        if handler_kind == "shellex" and isinstance(default_value, str):
                            stripped = default_value.strip()
                            if stripped.startswith("{") and stripped.endswith("}"):
                                clsid_value = stripped
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
                try:
                    *_counts, last_write = winreg.QueryInfoKey(key)
                    timestamp = datetime.fromtimestamp(last_write)
                except OSError:
                    timestamp = None
                display_name, icon, target_path = self._resolve_display_info(
                    handler_kind=handler_kind,
                    default_value=str(default_value) if default_value else "",
                    key_handle=key,
                    fallback_name=display_name,
                )
        except FileNotFoundError:
            return None
        status = "read-only" if read_only else ("enabled" if enabled else "disabled")
        return HandlerEntry(
            name=display_name,
            key_name=key_name,
            scope=scope,
            registry_path=registry_path,
            base_path=base_path,
            enabled=True if read_only else enabled,
            last_modified=timestamp,
            status=status,
            read_only=read_only,
            icon=icon,
            target_path=target_path,
            tooltip=self._format_tooltip(target_path, registry_path, status),
            handler_kind=handler_kind,
            clsid=clsid_value,
        )

    # ------------------------------------------------------------------ #
    # Metadata helpers
    # ------------------------------------------------------------------ #
    def _resolve_display_info(
        self,
        *,
        handler_kind: str,
        default_value: str,
        key_handle,
        fallback_name: str,
    ) -> Tuple[str, Optional[QIcon], Optional[str]]:
        if handler_kind == "shellex":
            return self._resolve_shellex_info(default_value, fallback_name)
        return self._resolve_shell_info(key_handle, fallback_name, default_value)

    def _resolve_shellex_info(self, default_value: str, fallback_name: str) -> Tuple[str, Optional[QIcon], Optional[str]]:
        clsid = default_value.strip()
        display_name = fallback_name
        target_path: Optional[str] = None
        icon: Optional[QIcon] = None
        if clsid.startswith("{") and clsid.endswith("}"):
            name, server_path = self._clsid_to_name(clsid, fallback_name)
            display_name = name or fallback_name
            target_path = server_path
            icon = self._icon_from_file(server_path)
        else:
            product_name = self._file_product_name(default_value)
            if product_name:
                display_name = product_name
        return display_name, icon, target_path

    def _resolve_shell_info(
        self,
        key_handle,
        fallback_name: str,
        default_value: str,
    ) -> Tuple[str, Optional[QIcon], Optional[str]]:
        display_name = self._safe_query_value(key_handle, "MUIVerb") or default_value or fallback_name
        if display_name.startswith("@"):
            resolved = self._resolve_mui_string(display_name)
            if resolved:
                display_name = resolved

        icon_value = self._safe_query_value(key_handle, "Icon")
        icon, icon_path = self._icon_from_icon_value(icon_value)
        command_target = self._read_command_target(key_handle)
        target_path = icon_path or command_target
        if not icon and not target_path and default_value:
            icon = self._icon_from_file(default_value)
            target_path = default_value
        return display_name, icon, target_path

    def _safe_query_value(self, key_handle, name: Optional[str]) -> str:
        try:
            value, _ = winreg.QueryValueEx(key_handle, name)
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-16le")
                except UnicodeDecodeError:
                    value = value.decode("utf-8", errors="ignore")
            return str(value)
        except FileNotFoundError:
            return ""
        except OSError:
            return ""

    def _resolve_mui_string(self, value: str) -> str:
        buffer = ctypes.create_unicode_buffer(MAX_PATH)
        try:
            res = shlwapi.SHLoadIndirectString(value, buffer, MAX_PATH, None)
            if res == 0:
                return buffer.value.strip()
        except Exception:
            self.logger.debug("Failed to resolve MUI string: %s", value, exc_info=True)
        return value

    def _parse_icon_location(self, value: str) -> Tuple[str, int]:
        cleaned = value.strip().strip('"')
        if cleaned.startswith("@"):
            cleaned = cleaned[1:]
        if "," in cleaned:
            path_part, index_part = cleaned.split(",", 1)
            try:
                return path_part.strip().strip('"'), int(index_part.strip())
            except ValueError:
                return path_part.strip().strip('"'), 0
        return cleaned, 0

    def _icon_from_icon_value(self, value: str) -> Tuple[Optional[QIcon], Optional[str]]:
        if not value:
            return None, None
        path, index = self._parse_icon_location(value)
        expanded = self._expand_path(path)
        if not expanded:
            return None, None
        icon = self._icon_from_file(expanded, index)
        return icon, expanded

    def _clsid_to_name(self, clsid: str, fallback: str) -> Tuple[str, Optional[str]]:
        display_name = ""
        server_path: Optional[str] = None
        try:
            with winreg.OpenKey(HKCR, f"CLSID\\{clsid}", 0, READ_FLAGS) as clsid_key:
                display_name = self._safe_query_value(clsid_key, None)
                try:
                    with winreg.OpenKey(clsid_key, "InprocServer32", 0, READ_FLAGS) as inproc_key:
                        server_path = self._safe_query_value(inproc_key, None)
                except FileNotFoundError:
                    pass
        except FileNotFoundError:
            pass
        expanded = self._expand_path(server_path)
        if not display_name:
            display_name = self._file_product_name(expanded) or clsid or fallback
        return display_name or fallback, expanded

    def _read_command_target(self, key_handle) -> Optional[str]:
        try:
            with winreg.OpenKey(key_handle, "command", 0, READ_FLAGS) as command_key:
                value = self._safe_query_value(command_key, None)
                return value or None
        except FileNotFoundError:
            return None

    def _expand_path(self, path: Optional[str]) -> Optional[str]:
        if not path:
            return None
        stripped = path.strip().strip('"')
        if not stripped:
            return None
        expanded = os.path.expandvars(stripped)
        return expanded

    def _icon_from_file(self, path: Optional[str], index: int = 0) -> Optional[QIcon]:
        if not path:
            return None
        expanded = self._expand_path(path)
        if not expanded:
            return None
        cache_key = f"{expanded}|{index}"
        if cache_key in self._icon_cache:
            return self._icon_cache[cache_key]
        try:
            large = wintypes.HICON()
            small = wintypes.HICON()
            extracted = shell32.ExtractIconExW(expanded, index, ctypes.byref(large), ctypes.byref(small), 1)
            handles = [large.value, small.value]
            chosen = small.value or large.value
            icon = None
            if extracted > 0 and chosen:
                icon = self._icon_from_handle(chosen)
                for handle in handles:
                    if handle and handle != chosen:
                        self._destroy_icon_handle(handle)
            if not icon:
                info = SHFILEINFO()
                flags = SHGFI_ICON | SHGFI_SMALLICON
                if not os.path.exists(expanded):
                    flags |= SHGFI_USEFILEATTRIBUTES
                res = shell32.SHGetFileInfoW(expanded, 0, ctypes.byref(info), ctypes.sizeof(info), flags)
                if res and info.hIcon:
                    icon = self._icon_from_handle(info.hIcon)
            if icon:
                self._icon_cache[cache_key] = icon
            return icon
        except Exception:
            self.logger.debug("Failed to extract icon from %s", expanded, exc_info=True)
            return None

    def _icon_from_handle(self, handle) -> Optional[QIcon]:
        if not handle:
            return None
        pixmap = QPixmap.fromWinHICON(int(handle))
        self._destroy_icon_handle(handle)
        if pixmap.isNull():
            return None
        return QIcon(pixmap)

    def _destroy_icon_handle(self, handle):
        if not handle:
            return
        try:
            user32.DestroyIcon(handle)
        except Exception:
            pass

    def _file_product_name(self, path: Optional[str]) -> Optional[str]:
        expanded = self._expand_path(path)
        if not expanded or not os.path.exists(expanded):
            return None
        try:
            handle = wintypes.DWORD()
            size = version.GetFileVersionInfoSizeW(expanded, ctypes.byref(handle))
            if not size:
                return None
            data = ctypes.create_string_buffer(size)
            if not version.GetFileVersionInfoW(expanded, 0, size, data):
                return None
            translate_ptr = ctypes.c_void_p()
            translate_len = wintypes.UINT()
            langs: List[Tuple[int, int]] = []
            if version.VerQueryValueW(data, r"\\VarFileInfo\\Translation", ctypes.byref(translate_ptr), ctypes.byref(translate_len)):
                entry_count = translate_len.value // ctypes.sizeof(wintypes.WORD) // 2
                array_type = wintypes.WORD * (entry_count * 2)
                translations = ctypes.cast(translate_ptr.value, ctypes.POINTER(array_type)).contents
                for i in range(entry_count):
                    lang = translations[i * 2]
                    codepage = translations[i * 2 + 1]
                    langs.append((lang, codepage))
            if not langs:
                langs.append((0x0409, 0x04B0))
            for lang, codepage in langs:
                sub_block = f"\\StringFileInfo\\{lang:04X}{codepage:04X}\\ProductName"
                value_ptr = ctypes.c_void_p()
                value_len = wintypes.UINT()
                if version.VerQueryValueW(data, sub_block, ctypes.byref(value_ptr), ctypes.byref(value_len)):
                    if value_ptr.value:
                        return ctypes.wstring_at(value_ptr.value, value_len.value).strip()
        except Exception:
            self.logger.debug("Failed to query version info for %s", expanded, exc_info=True)
        return None

    def _format_tooltip(self, target_path: Optional[str], registry_path: str, status: str) -> str:
        target = target_path or "不明"
        full_key = f"HKEY_CLASSES_ROOT\\{registry_path}"
        return f"実体: {target}\nキー: {full_key}\n状態: {status}"

    def clsid_registry_path(self, entry: HandlerEntry) -> Optional[str]:
        clsid = entry.clsid
        if not clsid:
            return None
        return f"HKEY_CLASSES_ROOT\\CLSID\\{clsid}"

    # ------------------------------------------------------------------ #
    # Enable / Disable
    # ------------------------------------------------------------------ #
    def toggle_handler(self, entry: HandlerEntry, enable: bool):
        if entry.read_only:
            raise RegistryOperationError("この項目は読み取り専用です。")
        if enable == entry.enabled:
            return
        source = entry.registry_path
        destination = self._compose_destination(entry.base_path, entry.key_name, enable)
        if not enable:
            self._ensure_disabled_parent(entry.base_path)
        self._move_tree(source, destination)
        entry.registry_path = destination
        entry.enabled = enable
        entry.status = "enabled" if enable else "disabled"

    def _compose_destination(self, base_path: str, key_name: str, enable: bool) -> str:
        if enable:
            return f"{base_path}\\{key_name}"
        return f"{base_path}\\DisabledHandlers\\{key_name}"

    def _ensure_disabled_parent(self, base_path: str):
        disabled_parent = f"{base_path}\\DisabledHandlers"
        winreg.CreateKeyEx(HKCR, disabled_parent, 0, WRITE_FLAGS).Close()

    def _move_tree(self, source_path: str, destination_path: str):
        if source_path == destination_path:
            return
        self.logger.info("Moving %s -> %s", source_path, destination_path)
        self._delete_tree(destination_path)
        self._copy_tree(source_path, destination_path)
        self._delete_tree(source_path)

    def _copy_tree(self, source_path: str, destination_path: str):
        try:
            with winreg.OpenKey(HKCR, source_path, 0, READ_FLAGS) as src_key:
                dest_key = winreg.CreateKeyEx(HKCR, destination_path, 0, WRITE_FLAGS)
                try:
                    self._copy_values(src_key, dest_key)
                    index = 0
                    while True:
                        try:
                            child_name = winreg.EnumKey(src_key, index)
                        except OSError:
                            break
                        index += 1
                        child_source = f"{source_path}\\{child_name}"
                        child_destination = f"{destination_path}\\{child_name}"
                        self._copy_tree(child_source, child_destination)
                finally:
                    dest_key.Close()
        except FileNotFoundError as exc:
            raise RegistryOperationError(f"Source key not found: {source_path}") from exc

    def _copy_values(self, src_key, dest_key):
        index = 0
        while True:
            try:
                name, value, value_type = winreg.EnumValue(src_key, index)
            except OSError:
                break
            index += 1
            winreg.SetValueEx(dest_key, name, 0, value_type, value)

    def _delete_tree(self, path: str):
        try:
            with winreg.OpenKey(HKCR, path, 0, WRITE_FLAGS) as key:
                child_names = []
                index = 0
                while True:
                    try:
                        child_names.append(winreg.EnumKey(key, index))
                    except OSError:
                        break
                    index += 1
        except FileNotFoundError:
            return
        for child in child_names:
            self._delete_tree(f"{path}\\{child}")
        winreg.DeleteKey(HKCR, path)

    # ------------------------------------------------------------------ #
    # Backup / Restore
    # ------------------------------------------------------------------ #
    def export_to_reg(self, entries: Iterable[HandlerEntry], destination: Path) -> int:
        paths: List[str] = []
        seen = set()
        for entry in entries:
            if entry.read_only:
                continue
            if entry.registry_path not in seen:
                seen.add(entry.registry_path)
                paths.append(entry.registry_path)
        if not paths:
            return 0
        lines = [REG_HEADER, ""]
        for path in paths:
            lines.append(f"[HKEY_CLASSES_ROOT\\{path}]")
            values = self._dump_values(path)
            if values:
                lines.extend(values)
            lines.append("")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("\n".join(lines), encoding="utf-16le")
        return len(paths)

    def _dump_values(self, path: str) -> List[str]:
        try:
            with winreg.OpenKey(HKCR, path, 0, READ_FLAGS) as key:
                rows: List[str] = []
                index = 0
                while True:
                    try:
                        name, value, value_type = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    rows.append(self._format_reg_value(name, value, value_type))
                return rows
        except FileNotFoundError:
            return []

    def _format_reg_value(self, name: Optional[str], value, value_type: int) -> str:
        target_name = "@" if name in (None, "") else f"\"{name}\""
        if value_type in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            escaped = str(value).replace("\\", "\\\\").replace("\"", "\\\"")
            return f"{target_name}=\"{escaped}\""
        if value_type == winreg.REG_DWORD:
            return f"{target_name}=dword:{int(value):08x}"
        if value_type == winreg.REG_BINARY:
            hex_bytes = ",".join(f"{byte:02x}" for byte in value)
            return f"{target_name}=hex:{hex_bytes}"
        # fallback to string
        escaped = str(value).replace("\\", "\\\\").replace("\"", "\\\"")
        return f"{target_name}=\"{escaped}\""

    def restore_from_reg(self, source: Path) -> Dict[str, int]:
        if not source.exists():
            raise FileNotFoundError(source)
        content = source.read_text(encoding="utf-16le")
        summary = {"success": 0, "skipped": 0, "failed": 0}
        current_path: Optional[str] = None
        buffer: List[str] = []
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(";") or line == REG_HEADER:
                continue
            if line.startswith("[") and line.endswith("]"):
                if current_path:
                    self._apply_block(current_path, buffer, summary)
                current_path = line[1:-1]
                buffer = []
            else:
                buffer.append(line)
        if current_path:
            self._apply_block(current_path, buffer, summary)
        return summary

    def _apply_block(self, full_path: str, values: List[str], summary: Dict[str, int]):
        prefix = "HKEY_CLASSES_ROOT\\"
        if not full_path.startswith(prefix):
            summary["skipped"] += 1
            return
        relative = full_path[len(prefix) :]
        try:
            key = winreg.CreateKeyEx(HKCR, relative, 0, WRITE_FLAGS)
            try:
                if not values:
                    winreg.SetValueEx(key, None, 0, winreg.REG_SZ, "")
                else:
                    for line in values:
                        name, parsed_value, value_type = self._parse_value_line(line)
                        winreg.SetValueEx(key, name, 0, value_type, parsed_value)
            finally:
                key.Close()
        except OSError:
            summary["failed"] += 1
        else:
            summary["success"] += 1

    def _parse_value_line(self, line: str) -> Tuple[Optional[str], object, int]:
        name: Optional[str]
        if line.startswith("@="):
            name = None
            payload = line[2:]
        elif line.startswith("\""):
            end_idx = line.find("\"", 1)
            name = line[1:end_idx]
            payload = line[end_idx + 1 :].lstrip("=")
        else:
            raise RegistryOperationError(f"Invalid .reg value line: {line}")

        if payload.startswith("dword:"):
            value = int(payload[len("dword:") :], 16)
            return name, value, winreg.REG_DWORD
        if payload.startswith("hex:"):
            bytes_str = payload[len("hex:") :].replace("\\", "").replace("\n", "")
            data = bytes(int(part, 16) for part in bytes_str.split(",") if part)
            return name, data, winreg.REG_BINARY
        if payload.startswith("\"") and payload.endswith("\""):
            text = payload[1:-1]
            unescaped = text.replace("\\\"", "\"").replace("\\\\", "\\")
            return name, unescaped, winreg.REG_SZ
        return name, payload, winreg.REG_SZ

    # ------------------------------------------------------------------ #
    # CSV export
    # ------------------------------------------------------------------ #
    def export_to_csv(self, entries: Iterable[HandlerEntry], destination: Path) -> int:
        rows = [entry.to_csv_row() for entry in entries]
        if not rows:
            return 0
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["名前", "スコープ", "状態", "レジストリパス", "最終変更日時"])
            writer.writerows(rows)
        return len(rows)

    # ------------------------------------------------------------------ #
    # Shell helper
    # ------------------------------------------------------------------ #
    def restart_explorer(self):
        subprocess.run(["taskkill", "/IM", "explorer.exe", "/F"], check=False)
        subprocess.Popen(["explorer.exe"])
