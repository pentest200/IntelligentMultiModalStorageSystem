@echo off
title File Organizer + MinIO Cloud Storage
echo ========================================
echo    File Organizer + MinIO Cloud Storage
echo ========================================
echo.

echo Step 1: Starting MinIO Cloud Storage...
echo MinIO API: http://localhost:9000
echo MinIO Console: http://localhost:9001
echo Credentials: minioadmin / minioadmin
echo.
start "MinIO Server" /D "C:\minio" minio.exe server C:\minio\data --console-address ":9001"

echo Step 2: Waiting for MinIO to initialize...
timeout /t 5

echo Step 3: Starting File Organizer Application...
cd /d "C:\Users\Ujjwal Shreshtha\OneDrive\Documents\fileVault"
npm start

echo.
echo ========================================
echo    Services Started Successfully!
echo ========================================
echo File Organizer: http://localhost:3000
echo MinIO Console:  http://localhost:9001
echo MinIO Credentials: minioadmin / minioadmin
echo.
echo Press any key to stop all services...
pause >nul

echo Stopping services...
taskkill /f /im minio.exe >nul 2>&1
taskkill /f /im node.exe >nul 2>&1
echo All services stopped.