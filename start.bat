@echo off
title Pasha Threat Analyser Launcher
cls
echo =================================================================
echo             PASHA THREAT ANALYSER - QUICK LAUNCHER
echo =================================================================
echo.
echo   [1] Start Full Application (Backend API + Frontend UI)
echo   [2] Start Backend API only  (http://localhost:8000)
echo   [3] Start Frontend UI only  (http://localhost:3000)
echo   [4] Run Local Agent Host Security Scan
echo   [5] Run Test Suite
echo   [6] Exit
echo.
echo =================================================================
set /p choice="Select an option (1-6): "

if "%choice%"=="1" (
    echo Starting Backend in a new window...
    start "Pasha Backend API" cmd /k "cd /d %~dp0backend && python main.py"
    echo Starting Frontend UI in a new window...
    start "Pasha Frontend UI" cmd /k "cd /d %~dp0frontend && npm.cmd run dev"
    echo.
    echo [OK] Both servers are starting up!
    echo   - Backend API: http://localhost:8000 (Docs: http://localhost:8000/docs)
    echo   - Frontend UI: http://localhost:3000
    pause
    exit /b
)

if "%choice%"=="2" (
    echo Starting Backend API on http://localhost:8000 ...
    cd /d "%~dp0backend"
    python main.py
    pause
    exit /b
)

if "%choice%"=="3" (
    echo Starting Frontend UI on http://localhost:3000 ...
    cd /d "%~dp0frontend"
    npm.cmd run dev
    pause
    exit /b
)

if "%choice%"=="4" (
    echo Running Pasha Local Agent Telemetry Scanner...
    cd /d "%~dp0backend"
    python agent\main.py
    pause
    exit /b
)

if "%choice%"=="5" (
    echo Running Test Suite...
    cd /d "%~dp0backend"
    python run_tests.py
    pause
    exit /b
)

if "%choice%"=="6" (
    exit /b
)

echo Invalid choice.
pause
