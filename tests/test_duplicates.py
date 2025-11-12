import os
import sys
from datetime import datetime
from pathlib import Path

import pytest

from src.models import HandlerEntry
from src.registry import (
    DuplicateGroup,
    RegistryManager,
    group_duplicates,
    export_to_reg,
    LCM_QUARANTINE_SEG,
    audit_append,
    is_quarantined,
    restore_quarantined,
)


def build_handler(name: str, key_path: str, kind: str, command: str = "", normalized: str = ""):
    return HandlerEntry(
        name=name,
        type=kind,
        scope="*",
        key_name=name,
        registry_path=key_path,
        full_key_path=f"HKEY_CLASSES_ROOT\\{key_path}",
        base_path=key_path.rsplit("\\", 1)[0] if "\\" in key_path else key_path,
        base_rel_path=key_path.rsplit("\\", 1)[0] if "\\" in key_path else key_path,
        enabled=True,
        last_modified=None,
        last_write_time=None,
        status="enabled",
        normalized_name=normalized or name.lower(),
        command=command,
        normalized_command=command.lower().strip(),
    )


def test_group_duplicates():
    handlers = [
        build_handler("Open", "*\\shell\\Open", "verb", 'C:\\App\\Tool.exe "%1"', "open"),
        build_handler("open", "*\\shell\\OpenAgain", "verb", 'C:\\App\\Tool.exe "%1"', "open"),
    ]
    groups = group_duplicates(handlers)
    assert groups
    found = [g for g in groups if g.reason == "command"]
    assert found
    assert found[0].suggested_keep_index == 0


@pytest.mark.skipif(sys.platform != "win32", reason="Windows registry operation")
def test_quarantine_restore(monkeypatch):
    entry = build_handler("QuarantineMe", "*\\shell\\QuarantineMe", "verb")
    entry.full_key_path = f"HKEY_CLASSES_ROOT\\{LCM_QUARANTINE_SEG}\\{entry.registry_path}"
    rm = RegistryManager()

    rm._read_registry_value = lambda path, name: f"HKEY_CLASSES_ROOT\\{entry.registry_path}"
    exists_calls = []
    def fake_exists(path):
        exists_calls.append(path)
        return len(exists_calls) < 2
    rm._key_exists = fake_exists
    moved = []
    rm.move_key = lambda src, dst: moved.append((src, dst))
    dest = restore_quarantined(entry, rm)
    assert dest.endswith("-2")
    assert moved


def test_is_quarantined_flag():
    entry = build_handler("QuarantineMe", "*\\shell\\QuarantineMe", "verb")
    entry.full_key_path = f"HKEY_CLASSES_ROOT\\{LCM_QUARANTINE_SEG}\\{entry.registry_path}"
    assert is_quarantined(entry)

@pytest.mark.skipif(sys.platform != "win32", reason="audit log writes only on Windows")
def test_audit_append(tmp_path, monkeypatch):
    entry = build_handler("AuditMe", "*\\shell\\AuditMe", "verb")
    entry.full_key_path = f"HKEY_CLASSES_ROOT\\{entry.registry_path}"
    os.environ["LOCALAPPDATA"] = str(tmp_path)
    rm = RegistryManager()
    audit_append("duplicate_quarantine", entry, "src", "dst", True)
    pattern = tmp_path / "LightContextMenuManager" / "audit" / f"audit_{datetime.utcnow():%Y%m%d}.csv"
    assert pattern.exists()
    content = pattern.read_text(encoding="utf-8-sig")
    assert "duplicate_quarantine" in content
