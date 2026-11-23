@echo off
title VentaFlow POS
echo ===================================================
echo   Iniciando VentaFlow POS en Modo Aplicacion...
echo ===================================================
start "" python server.py
timeout /t 2 /nobreak >nul
where msedge >nul 2>nul
if %errorlevel%==0 (
  start "" msedge --app=http://localhost:8080
) else (
  start "" chrome --app=http://localhost:8080
)
