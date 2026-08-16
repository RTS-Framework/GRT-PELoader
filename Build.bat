@echo off

echo ========== initialize Visual Studio environment ==========
if "%VisualStudio%" == "" (
    echo environment variable "VisualStudio" is not set
    exit /b 1
)
call "%VisualStudio%\VC\Auxiliary\Build\vcvars64.bat"

echo ================== clean outdated dist ===================
del /S /Q dist

echo =============== clean outdated build files ===============
rd /S /Q "Release"
rd /S /Q "x64"
rd /S /Q "builder\Release"
rd /S /Q "builder\x64"
rd /S /Q "cutter\Release"
rd /S /Q "cutter\x64"

echo ==================== generate builder ====================
MSBuild.exe GRT-PELoader.sln /t:builder /p:Configuration=Release /p:Platform=x86
MSBuild.exe GRT-PELoader.sln /t:builder /p:Configuration=Release /p:Platform=x64

echo ==================== generate cutter =====================
MSBuild.exe GRT-PELoader.sln /t:cutter /p:Configuration=Release /p:Platform=x86
MSBuild.exe GRT-PELoader.sln /t:cutter /p:Configuration=Release /p:Platform=x64

echo =============== extract PE Loader template ===============
cd builder
echo --------extract template for x86--------
"..\Release\builder.exe"
echo --------extract template for x64--------
"..\x64\Release\builder.exe"
cd ..

cd cutter
echo ----------cut PE Loader for x86----------
"..\Release\cutter.exe"
echo ----------cut PE Loader for x64----------
"..\x64\Release\cutter.exe"
cd ..

echo ================= copy standard template =================
copy /Y dist\standard\*.bin loader\template

echo =================== clean build files ====================
rd /S /Q "Release"
rd /S /Q "x64"
rd /S /Q "builder\Release"
rd /S /Q "builder\x64"
rd /S /Q "cutter\Release"
rd /S /Q "cutter\x64"

echo ================ generate assembly module ================
go run dump.go

echo =================== test loader package ==================
call test.bat
if errorlevel 1 (
    echo.
    echo failed to test loader package!
    exit /b %ERRORLEVEL%
)

echo ==========================================================
echo                 build template finish!
echo ==========================================================
pause
