@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher not found. Install Python 3.12+ and enable Add to PATH.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  py -3.12 -m venv .venv
  if errorlevel 1 py -m venv .venv
)
if not exist ".env" copy ".env.example" ".env" >nul
call ".venv\Scripts\activate.bat"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo Dependency installation failed. Check your internet connection and Python version.
  pause
  exit /b 1
)
echo.
echo RelayChat X will open at http://localhost:8000
 echo Demo verification codes will be printed here until SMTP and Twilio are configured.
echo Press Ctrl+C to stop the server.
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
pause
