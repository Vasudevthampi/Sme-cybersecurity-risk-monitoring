@echo off
setlocal
title SME Cybersecurity Risk Monitor

if defined JAVA_HOME (
    set "JAVA_CMD=%JAVA_HOME%\bin\java.exe"
    set "PATH=%JAVA_HOME%\bin;%PATH%"
) else (
    set "JAVA_CMD=java.exe"
)

cd /d "%~dp0"

echo ======================================================================
echo    Starting Small and Medium Enterprises Cybersecurity Risk Monitor
echo ======================================================================
echo [1/3] Using Java runtime: %JAVA_CMD%

if not exist "%~dp0target\sme-cyber-risk-monitor-1.0.0.jar" (
    echo [2/3] Executable JAR not found. Building with Maven wrapper...
    call "%~dp0mvnw.cmd" package -DskipTests=true
    if errorlevel 1 (
        echo Build failed. Check that Java and Maven are installed and configured.
        exit /b 1
    )
) else (
    echo [2/3] Found pre-built executable JAR: target\sme-cyber-risk-monitor-1.0.0.jar
)

if not exist "%~dp0target\sme-cyber-risk-monitor-1.0.0.jar" (
    echo Build did not produce the executable JAR.
    exit /b 1
)

echo [3/3] Launching application on http://localhost:8085 ...
echo.
echo Open your web browser to:
echo   --^> Dashboard:        http://localhost:8085/
echo   --^> Asset Inventory:  http://localhost:8085/assets
echo   --^> NIST CSF Audit:   http://localhost:8085/compliance
echo   --^> Risk Playbook:    http://localhost:8085/playbook
echo   --^> Executive Report: http://localhost:8085/report
echo   --^> H2 Database DB:   http://localhost:8085/h2-console
echo.
echo (Press Ctrl+C to stop the server at any time)
echo ======================================================================
echo.

"%JAVA_CMD%" -jar "%~dp0target\sme-cyber-risk-monitor-1.0.0.jar"
pause
