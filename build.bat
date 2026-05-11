@echo off
setlocal
echo Delegating to build.py...
python build.py %*
endlocal
