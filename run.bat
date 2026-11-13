@echo off
setlocal
title SME Cybersecurity Risk Monitor

if "%JAVA_HOME%"=="" (
    set "JAVA_HOME=C:\Users\siirr\.p2\pool\plugins\org.eclipse.justj.openjdk.hotspot.jre.full.win32.x86_64_21.0.10.v20260205-0638\jre"
)
set "PATH=%JAVA_HOME%\bin;%PATH%"

cd /d "%~dp0"

echo ======================================================================
echo    Starting Small and Medium Enterprises Cybersecurity Risk Monitor
echo ======================================================================
echo [1/3] Using Java runtime: %JAVA_HOME%\bin\java.exe

if not exist "%~dp0target\sme-cyber-risk-monitor-1.0.0.jar" (
    echo [2/3] Executable JAR not found. Building with Maven wrapper...
    call "%~dp0mvnw.cmd" package -DskipTests=true
) else (
    echo [2/3] Found pre-built executable JAR: target\sme-cyber-risk-monitor-1.0.0.jar
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

"%JAVA_HOME%\bin\java.exe" -jar "%~dp0target\sme-cyber-risk-monitor-1.0.0.jar"
pause
