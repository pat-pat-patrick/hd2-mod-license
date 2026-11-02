@echo off
rem Tests, then builds release\HD2QD.License.dll, the license plugin of HD2 Mod Quick Deploy
rem (added on its Plugins page). Needs the .NET SDK (8 or later): dotnet on PATH, or set
rem DOTNET to its dotnet.exe.
cd /d "%~dp0"
if "%DOTNET%"=="" set DOTNET=dotnet
"%DOTNET%" test tests\License.Tests.csproj || exit /b 1
"%DOTNET%" build src\HD2QD.License.csproj -c Release || exit /b 1
if not exist release mkdir release
copy /y "src\bin\Release\net48\HD2QD.License.dll" "release\HD2QD.License.dll" >nul || exit /b 1
echo.
echo Built: plugin\release\HD2QD.License.dll
