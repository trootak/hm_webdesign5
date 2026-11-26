@echo off
cd /d "%~dp0"
node --version || (echo Install Node.js 22.13 or later first.& pause & exit /b 1)
if not exist node_modules\express\package.json call npm install
start "" http://localhost:3000
node server.js
pause
