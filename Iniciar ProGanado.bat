# ============================================================
#  ProGanado — arranque con un solo click
#  Inicia el servidor local (página + códigos de seguridad)
#  y abre la página en tu navegador.
# ============================================================
@echo off
title ProGanado — Servidor
cd /d "%~dp0"
echo.
echo   Iniciando ProGanado...
echo   Se abrira tu navegador en:  http://127.0.0.1:8899/index.html
echo   Para detener: cierra esta ventana
echo.
start "" http://127.0.0.1:8899/index.html
python servidor.py
pause