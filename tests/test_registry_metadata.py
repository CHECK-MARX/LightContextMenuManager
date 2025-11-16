from pathlib import Path

from src.registry import RegistryManager


def test_guess_company_from_path():
    manager = RegistryManager()
    assert manager._guess_company_from_path("C:\\Program Files\\Trend Micro\\app.dll") == "Trend Micro"
    assert manager._guess_company_from_path("C:\\Windows\\Microsoft.NET\\foo.exe") == "Microsoft"
    assert manager._guess_company_from_path("C:\\drivers\\NVIDIA Corp\\bar.dll") == "NVIDIA"
    assert manager._guess_company_from_path("C:\\unknown\\app.exe") is None


def test_resolve_handler_metadata_guesses_company():
    manager = RegistryManager()
    metadata = manager.resolve_handler_metadata(
        type("Dummy", (), {"type": "shell", "command": r"C:\Windows\notepad.exe", "clsid": None})()
    )
    assert isinstance(metadata["company"], str)
