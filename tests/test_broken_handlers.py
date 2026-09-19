from typing import Optional

import pytest

from src.models import HandlerEntry
from src.registry import RegistryManager


def _build_entry(kind: str) -> HandlerEntry:
    base_path = "*\\shell"
    return HandlerEntry(
        name="Test",
        type=kind,
        scope="*",
        key_name="Test",
        registry_path=f"{base_path}\\Test",
        full_key_path=f"HKEY_CLASSES_ROOT\\{base_path}\\Test",
        base_path=base_path,
        base_rel_path=base_path,
        enabled=True,
        last_modified=None,
        last_write_time=None,
        status="enabled",
        normalized_name="test",
        command=None,
    )


def test_shell_entry_missing_executable():
    entry = _build_entry("verb")
    entry.command = r'C:\does_not_exist\tool.exe "%1"'
    manager = RegistryManager()
    broken, reason = manager._evaluate_handler_integrity(entry, "shell")
    assert broken
    assert reason == "missing_exe"


def test_shell_entry_missing_guid():
    entry = _build_entry("verb")
    entry.command = None
    entry.clsid = None
    manager = RegistryManager()
    broken, reason = manager._evaluate_handler_integrity(entry, "shell")
    assert broken
    assert reason == "missing_guid"


def test_shellex_entry_missing_clsid(monkeypatch):
    entry = _build_entry("shellex")
    entry.clsid = "{00000000-0000-0000-0000-000000000000}"
    manager = RegistryManager()
    monkeypatch.setattr(RegistryManager, "_clsid_server_path", lambda self, clsid: None)
    broken, reason = manager._evaluate_handler_integrity(entry, "shellex")
    assert broken
    assert reason == "missing_clsid"


def test_resolve_command_executable_variants():
    manager = RegistryManager()
    result = manager.resolve_command_executable(r'"C:\Program Files\App\tool.exe" "%1"')
    assert result == r"C:\Program Files\App\tool.exe"
    result = manager.resolve_command_executable(r"C:\App\tool.exe /x")
    assert result == r"C:\App\tool.exe"


def test_slugify_handler_name_strips_bad_chars():
    manager = RegistryManager()
    slug = manager._slugify_handler_name("Cursor で開く！")
    assert slug == "cursor"
