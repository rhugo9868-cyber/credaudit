@echo off
chcp 65001 >nul
rem CredAudit - start with one double click. Needs Python 3.10+.
cd /d "%~dp0"
set PY=
py -3 -c "import sys" >nul 2>nul && set PY=py -3
if not defined PY (
  python -c "import sys" >nul 2>nul && set PY=python
)
if not defined PY (
  echo.
  echo  Python ne ustanovlen / Python is not installed.
  echo.
  echo  1. Otkroyte https://www.python.org/downloads/ i skachayte Python.
  echo  2. V ustanovshchike OBYAZATELNO otmette galochku "Add python.exe to PATH".
  echo  3. Posle ustanovki zakroyte eto okno i snova dvazhdy shchelknite start.bat.
  echo.
  echo  Ili v terminale: winget install Python.Python.3.12
  echo.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo First run: preparing environment, please wait 1-2 minutes...
  %PY% -m venv .venv
  if errorlevel 1 ( echo venv failed & pause & exit /b 1 )
  ".venv\Scripts\python.exe" -m pip install -q -r backend\requirements.txt
  if errorlevel 1 ( echo pip install failed & pause & exit /b 1 )
)
".venv\Scripts\python.exe" run.py
pause
