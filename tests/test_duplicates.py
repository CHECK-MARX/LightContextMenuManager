import os
import sys
from datetime import datetime
from pathlib import Path

import pytest

from src.models import HandlerEntry
from src.registry import (
    RegistryManager,
    LCM_QUARANTINE_SEG,
    audit_append,
    group_duplicates,
    is_quarantined,
    restore_quarantined,
)

HKCR_PREFIX = "HKEY_CLASSES_ROOT\\"


def build_handler(name: str, key_path: str, kind: str, command: str = "", normalized: str = "") -> HandlerEntry:
    base = key_path.rsplit("\\", 1)[0] if "\\" in key_path else key_path
    return HandlerEntry(
        name=name,
        type=kind,
        scope="*",
        key_name=name,
        registry_path=key_path,
        full_key_path=f"{HKCR_PREFIX}{key_path}",
        base_path=base,
        base_rel_path=base,
        enabled=True,
        last_modified=None,
        last_write_time=None,
        status="enabled",
        normalized_name=normalized or name.lower(),
        command=command or None,
        normalized_command=command.lower().strip() if command else "",
    )


def test_group_duplicates():
    handlers = [
        build_handler("Open", "*\\shell\\Open", "verb", 'C:\\App\\Tool.exe "%1"', "open"),
        build_handler("open", "*\\shell\\OpenAgain", "verb", 'C:\\App\\Tool.exe "%1"', "open"),
    ]
    groups = group_duplicates(handlers)
    assert groups
    command_groups = [g for g in groups if g.reason == "command"]
    assert command_groups
    assert command_groups[0].suggested_keep_index == 0


def test_is_quarantined_flag():
    entry = build_handler("QuarantineMe", "*\\shell\\QuarantineMe", "verb")
    entry.registry_path = f"{LCM_QUARANTINE_SEG}\\{entry.registry_path}"
    entry.full_key_path = f"{HKCR_PREFIX}{entry.registry_path}"
    assert is_quarantined(entry)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows registry operation")
def test_restore_quarantined(monkeypatch):
    entry = build_handler("QuarantineMe", f"{LCM_QUARANTINE_SEG}\\QuarantineMe", "verb")
    entry.full_key_path = f"{HKCR_PREFIX}{entry.registry_path}"
    calls = {"exists": [], "moves": []}
    def fake_exists(path):
        calls["exists"].append(path)
        return len(calls["exists"]) == 1

    def fake_move(self, src, dst):
        calls["moves"].append((src, dst))

    monkeypatch.setattr("src.registry._lookup_registry_value", lambda path, name: "*\\shell\\QuarantineMe")
    monkeypatch.setattr("src.registry._registry_key_exists", fake_exists)
    monkeypatch.setattr(RegistryManager, "move_key", fake_move)

    dest = restore_quarantined(entry)
    assert dest.endswith("-2")
    assert calls["moves"][0][0] == entry.registry_path
    assert calls["moves"][0][1] == "*\\shell\\QuarantineMe-2"


@pytest.mark.skipif(sys.platform != "win32", reason="audit log writes only on Windows")
def test_audit_append(tmp_path, monkeypatch):
    entry = build_handler("AuditMe", "*\\shell\\AuditMe", "verb")
    entry.full_key_path = f"{HKCR_PREFIX}{entry.registry_path}"
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    audit_append("duplicate_quarantine", entry, "src", "dst", True)
    today = datetime.utcnow().strftime("%Y%m%d")
    audit_file = tmp_path / "LightContextMenuManager" / "audit" / f"audit_{today}.csv"
    assert audit_file.exists()
    content = audit_file.read_text(encoding="utf-8-sig")
    assert "duplicate_quarantine" in content
