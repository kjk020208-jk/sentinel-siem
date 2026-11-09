@echo off
cd /d %~dp0
if not exist node_modules (
  echo [SENTINEL] Installing React dependencies...
  call npm install
  if errorlevel 1 pause & exit /b 1
)
echo [SENTINEL] Starting React dashboard...
call npm run dev
