from src.registry import RegistryManager


def test_compose_destination_paths():
    manager = RegistryManager()
    base = r"*\\shellex\\ContextMenuHandlers"
    key = "Sample"

    enabled_path = manager._compose_destination(base, key, True)
    disabled_path = manager._compose_destination(base, key, False)

    assert enabled_path == rf"{base}\{key}"
    assert disabled_path == rf"{base}\DisabledHandlers\{key}"
    assert enabled_path != disabled_path
