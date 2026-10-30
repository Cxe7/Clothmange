@echo off
chcp 65001 >nul
echo Starting... open http://localhost:3000
node server.js
pause
