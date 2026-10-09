@echo off
setlocal
cd /d "%~dp0"
title Block Manager Analytics Portable V1.1
where python.exe >nul 2>&1
if errorlevel 1 (
 echo Python 3 nao foi encontrado neste computador.
 echo Instale Python 3 com sqlite3 e execute novamente.
 pause
 exit /b 1
)
python.exe app\server.py
pause
