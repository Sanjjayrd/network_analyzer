@echo off
echo ============================================
echo   Kerala Police CyberDome - CVIP Portal
echo ============================================

echo [1/3] Starting Backend API (FastAPI)...
start "CVIP Backend" cmd /k "cd /d "%~dp0backend" && uvicorn main:app --reload"

echo Waiting for backend to initialize...
timeout /t 4 /nobreak > NUL

echo [2/3] Starting React Web UI...
start "CVIP Frontend" cmd /k "cd /d "%~dp0web-ui" && npm run dev"

echo Waiting for Vite to start...
timeout /t 6 /nobreak > NUL

echo [3/3] Opening Browser...
start "" "http://localhost:5173/"

echo.
echo ============================================
echo   CVIP Portal is running!
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:5173
echo ============================================
