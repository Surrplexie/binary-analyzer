@echo off
setlocal

echo [1/2] Installing build dependencies...
pip install -r requirements.txt

echo [2/2] Building binary-analyzer.exe...
pyinstaller --onefile --name binary-analyzer main.py

echo.
echo Build complete: dist\binary-analyzer.exe
endlocal
