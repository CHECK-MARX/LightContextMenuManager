from __future__ import annotations

import csv
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import winreg

from .models import HandlerEntry

HKCR = winreg.HKEY_CLASSES_ROOT
READ_FLAGS = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
WRITE_FLAGS = winreg.KEY_READ | winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY

SHELLEX_TARGETS = [
    {"scope": "*", "path": r"*\shellex\ContextMenuHandlers"},
    {"scope": "Folder", "path": r"Folder\shellex\ContextMenuHandlers"},
    {"scope": "Directory Background", "path": r"Directory\Background\shellex\ContextMenuHandlers"},
    {"scope": "Drive", "path": r"Drive\shellex\ContextMenuHandlers"},
]

SHELL_TARGETS = [
    {"scope": "*", "path": r"*\shell"},
    {"scope": "Folder", "path": r"Folder\shell"},
]

REG_HEADER = "Windows Registry Editor Version 5.00"


class RegistryOperationError(Exception):
    """Raised when registry manipulation fails."""


class RegistryManager:
    """High-level operations for context menu handlers."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)

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
        collected: List[HandlerEntry] = []
        collected.extend(
            self._iterate_entries(
                parent_path=base_path,
                base_path=base_path,
                scope=scope,
                enabled=True,
                read_only=read_only,
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
    ) -> Optional[HandlerEntry]:
        try:
            with winreg.OpenKey(HKCR, registry_path, 0, READ_FLAGS) as key:
                display_name = key_name
                try:
                    default_value, _ = winreg.QueryValueEx(key, None)
                    if default_value:
                        display_name = str(default_value)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
                try:
                    *_counts, last_write = winreg.QueryInfoKey(key)
                    timestamp = datetime.fromtimestamp(last_write)
                except OSError:
                    timestamp = None
        except FileNotFoundError:
            return None
        status = "参照のみ" if read_only else ("有効" if enabled else "無効")
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
        )

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
        entry.status = "有効" if enable else "無効"

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
