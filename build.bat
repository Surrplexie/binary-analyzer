@echo off
setlocal

echo [1/2] Installing package with dev extras (PyInstaller)...
pip install -e ".[dev]"

echo [2/2] Building binary-analyzer.exe...
pyinstaller --onefile --name binary-analyzer -m binary_analyzer

echo.
echo Build complete: dist\binary-analyzer.exe
endlocal
