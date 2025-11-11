import pytest

from src.history import HistoryManager


def test_history_record_and_undo_redo(tmp_path):
    history = HistoryManager(limit=5)
    for idx in range(3):
        history.record(
            name=f"Item{idx}",
            registry_path=f"*\\shellex\\ContextMenuHandlers\\Key{idx}",
            key_name=f"Key{idx}",
            base_path="*\\shellex\\ContextMenuHandlers",
            scope="*",
            from_enabled=bool(idx % 2),
            to_enabled=not bool(idx % 2),
        )
    assert history.can_undo()

    entry = history.undo()
    assert entry is not None
    assert entry.name == "Item2"
    assert history.can_redo()

    redo_entry = history.redo()
    assert redo_entry.name == "Item2"

    out_file = tmp_path / "snapshot.json"
    history.save_snapshot(out_file)

    restored = HistoryManager()
    restored.load_snapshot(out_file)
    assert len(restored.snapshot_entries()) == len(history.last_entries())
    assert not restored.can_undo()
