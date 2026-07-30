"""Запуск из корневой папки проекта — делегирует в files/app.py."""
import runpy
from pathlib import Path

runpy.run_path(str(Path(__file__).resolve().parent / "files" / "app.py"), run_name="__main__")
