@echo off
rem Generating exe....
pyinstaller --onefile --name hiveEx.1.0 --icon ./icon/icon.ico ./src/main/main.py

rem Pause opcional para visualizar mensagens
pause
