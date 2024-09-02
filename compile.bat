@echo off
setlocal


if "%~1"=="x64" (
    set "ARCH=x64"
) else (
    set "ARCH=Win32"
)

echo ARCH is %ARCH%

:: 查找 vcpkg 的路径
for /f "delims=" %%i in ('where vcpkg') do set VCPKG_PATH=%%i

:: 输出找到的 vcpkg 路径
echo vcpkg path found: %VCPKG_PATH%

:: 确保 vcpkg 的路径存在
if not exist "%VCPKG_PATH%" (
    echo Error: vcpkg not found
    exit /b 1
)

:: 获取 vcpkg 根目录（去掉 vcpkg.exe 部分）
set VCPKG_ROOT=%VCPKG_PATH:~0,-10%

:: 使用 CMake 构建项目
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake  -A  %ARCH%
cmake --build .

endlocal
