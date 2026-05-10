@echo off
title ThreatSight Launcher
echo ============================================
echo   ThreatSight - Network Threat Detection
echo ============================================
echo.

:: ---- Configure tshark path ----
set "TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe"
if not exist "%TSHARK_PATH%" (
    echo [ERROR] tshark not found at: %TSHARK_PATH%
    echo Please install Wireshark or update the path in start.bat
    pause
    exit /b 1
)

:: ---- Step 1: Kill old processes on target ports ----
echo [1/5] Cleaning up old processes...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5000.*LISTENING" 2^>nul') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5174.*LISTENING" 2^>nul') do taskkill /F /PID %%a >nul 2>&1
timeout /t 2 /nobreak >nul

:: ---- Step 2: Activate venv ----
echo [2/5] Activating Python virtual environment...
if not exist "venv\Scripts\activate.bat" (
    echo [ERROR] venv not found! Run: python -m venv venv
    pause
    exit /b 1
)
call venv\Scripts\activate.bat

:: ---- Step 3: Install dependencies ----
echo [3/5] Checking dependencies...
pip install -r requirements.txt -q 2>nul
if %ERRORLEVEL% neq 0 (
    echo [WARNING] pip install had issues, continuing anyway...
)

:: ---- Step 4: Start backend (new window) ----
echo [4/5] Starting backend server (port 5000)...
set DEMO_MODE=true
start "ThreatSight Backend" cmd /k "set TSHARK_PATH=%TSHARK_PATH% && set DEMO_MODE=true && python app.py"
echo   Waiting for backend to be ready...
:wait_backend
timeout /t 1 /nobreak >nul
curl -s -o NUL http://127.0.0.1:5000/api/health 2>nul
if %ERRORLEVEL% neq 0 goto wait_backend
echo   Backend is up!

:: ---- Step 5: Start frontend (new window) ----
echo [5/5] Starting frontend dev server (port 5174)...
cd frontend
start "ThreatSight Frontend" npm run dev
cd ..
echo   Waiting for frontend to be ready...
:wait_frontend
timeout /t 1 /nobreak >nul
curl -s -o NUL http://127.0.0.1:5174 2>nul
if %ERRORLEVEL% neq 0 goto wait_frontend
echo   Frontend is up!

:: ---- Done: Open browser ----
echo.
echo ============================================
echo   ThreatSight is running!
echo   Dashboard:  http://127.0.0.1:5174
echo   API docs:   http://127.0.0.1:5000/apidocs
echo   API health: http://127.0.0.1:5000/api/health
echo ============================================
start http://127.0.0.1:5174
echo.
echo Close backend/frontend windows to stop, or press any key to exit this launcher.
pause >nul
