@echo off
if "%JAVA_HOME%"=="" (
    set "JAVA_HOME=C:\Users\siirr\.p2\pool\plugins\org.eclipse.justj.openjdk.hotspot.jre.full.win32.x86_64_21.0.10.v20260205-0638\jre"
)
set "PATH=%JAVA_HOME%\bin;%PATH%"
"C:\Users\siirr\.gemini\antigravity\scratch\tools\apache-maven-3.9.6\bin\mvn.cmd" %*
