@echo off
REM ============================================================
REM  ProGanado - arranque con un solo click
REM  Inicia el servidor local (pagina + codigos de seguridad)
REM  y abre la pagina en tu navegador.
REM ============================================================
title ProGanado - Servidor
cd /d "%~dp0"
echo.
echo   Iniciando ProGanado...
echo   Se abrira tu navegador en:  http://127.0.0.1:8899/index.html
echo   Para detener: cierra esta ventana
echo.
start "" http://127.0.0.1:8899/index.html
python servidor.py
pause
