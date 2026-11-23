@echo off
chcp 65001 >nul
title Publicar VentaFlow POS en la Nube
cd /d "%~dp0"

echo ============================================================
echo   ASISTENTE AUTOMATICO DE PUBLICACION - VENTAFLOW POS
echo ============================================================
echo.

echo [1/4] Verificando sesion en GitHub...
gh auth status >nul 2>nul
if %errorlevel% neq 0 (
    echo Necesitas autorizar tu cuenta de GitHub en el navegador.
    echo Se abrira una ventana para iniciar sesion con 1 clic...
    gh auth login --web -h github.com -p https
    if %errorlevel% neq 0 (
        echo [ERROR] No se pudo iniciar sesion en GitHub.
        pause
        exit /b 1
    )
)
echo [OK] GitHub conectado.
echo.

echo [2/4] Guardando ultimos cambios en Git...
git add . >nul 2>nul
git -c user.name="VentaFlow" -c user.email="admin@ventaflow.app" commit -m "Actualizacion automatica VentaFlow POS" >nul 2>nul

echo [3/4] Subiendo codigo a tu repositorio en GitHub...
git remote get-url origin >nul 2>nul
if %errorlevel% neq 0 (
    gh repo create ventaflow-pos --public --source=. --remote=origin --push
) else (
    git push -u origin master
)

if %errorlevel% neq 0 (
    echo [AVISO] Si el repo ya existia, intenta: git push -u origin master
    pause
)
echo [OK] Codigo subido a GitHub.
echo.

echo [4/4] Abriendo Render para desplegar con HTTPS en 1 clic...
echo En Render:
echo  1. Inicia sesion con tu cuenta de GitHub
echo  2. Elige "New Blueprint Instance" o "New Web Service"
echo  3. Selecciona tu repositorio "ventaflow-pos"
echo  4. Pega tu PLATFORM_MP_ACCESS_TOKEN (APP_USR-...) y haz clic en Deploy!
echo.
start "" "https://dashboard.render.com/select-repo?type=blueprint"
pause
