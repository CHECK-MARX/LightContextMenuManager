from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .models import HandlerEntry


@dataclass
class PresetRule:
    """Single enable/disable instruction."""

    enable: bool
    name_contains: Optional[str] = None
    scope: Optional[str] = None
    path_contains: Optional[str] = None

    def matches(self, entry: HandlerEntry) -> bool:
        if self.scope and self.scope.lower() != entry.scope.lower():
            return False
        if self.name_contains and self.name_contains.lower() not in entry.name.lower():
            return False
        if self.path_contains and self.path_contains.lower() not in entry.registry_path.lower():
            return False
        return True


@dataclass
class Preset:
    preset_id: str
    label: str
    description: str
    rules: List[PresetRule] = field(default_factory=list)

    def planned_changes(self, entries: Iterable[HandlerEntry]) -> Dict[str, bool]:
        """Return mapping of registry_path -> desired enabled state."""
        actions: Dict[str, bool] = {}
        for entry in entries:
            for rule in self.rules:
                if rule.matches(entry):
                    actions[entry.registry_path] = rule.enable
                    break
        return actions


class PresetManager:
    """Reads preset JSON definitions from presets/ folder."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.presets: Dict[str, Preset] = {}
        self.reload()

    def reload(self):
        self.presets.clear()
        if not self.directory.exists():
            return
        for json_file in self.directory.glob("*.json"):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            preset = self._parse_preset(data, json_file.stem)
            if preset:
                self.presets[preset.preset_id] = preset

    def _parse_preset(self, data: dict, fallback_id: str) -> Optional[Preset]:
        preset_id = data.get("id") or fallback_id
        label = data.get("label") or preset_id
        description = data.get("description", "")
        rules_data = data.get("rules", [])
        rules = []
        for rule in rules_data:
            rules.append(
                PresetRule(
                    enable=bool(rule.get("enable", True)),
                    name_contains=rule.get("name_contains"),
                    scope=rule.get("scope"),
                    path_contains=rule.get("path_contains"),
                )
            )
        return Preset(preset_id=preset_id, label=label, description=description, rules=rules)

    def list_presets(self) -> List[Preset]:
        return list(self.presets.values())

    def get(self, preset_id: str) -> Optional[Preset]:
        return self.presets.get(preset_id)
