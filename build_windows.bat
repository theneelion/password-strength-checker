@echo off
setlocal

where py >nul 2>nul
if errorlevel 1 (
    echo Python launcher "py" was not found.
    echo Install Python 3 and try again.
    pause
    exit /b 1
)

py -3 -m PyInstaller --noconfirm --clean --onefile --windowed --name "Password Checker" password_checker_app.py

if errorlevel 1 (
    echo.
    echo Build failed.
    pause
    exit /b 1
)

echo.
echo Build complete.
echo EXE: dist\Password Checker.exe
pause
endlocal
