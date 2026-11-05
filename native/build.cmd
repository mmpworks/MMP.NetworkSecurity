@echo off
rem Builds native\bin\<arch>\netsec_ct.dll as C++, then compiles the same source as C (program-design.md section 7).
rem Usage: native\build.cmd [x64^|x86]. Default x64. NSCT_VCBUILD overrides the folder that holds vcvars64.bat.
setlocal
set "ARCH=%~1"
if "%ARCH%"=="" set "ARCH=x64"
if /i "%ARCH%"=="x64" (set "VCVARS=vcvars64.bat") else if /i "%ARCH%"=="x86" (set "VCVARS=vcvars32.bat") else (echo build.cmd: unknown arch %ARCH% & exit /b 2)
if not defined NSCT_VCBUILD set "NSCT_VCBUILD=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build"
if not exist "%NSCT_VCBUILD%\%VCVARS%" (echo build.cmd: %VCVARS% not found in %NSCT_VCBUILD% & exit /b 91)
call "%NSCT_VCBUILD%\%VCVARS%" >nul
if errorlevel 1 exit /b 91
cd /d "%~dp0.."
if not exist "native\bin\%ARCH%" mkdir "native\bin\%ARCH%"
cl /nologo /W4 /WX /O2 /TP /LD /DNSCT_BUILD native\netsec_ct.c /Fenative\bin\%ARCH%\netsec_ct.dll /Fonative\bin\%ARCH%\
if errorlevel 1 exit /b 92
cl /nologo /W4 /WX /O2 /TC /c native\netsec_ct.c /Fonative\bin\%ARCH%\c_check.obj
if errorlevel 1 exit /b 93
endlocal
