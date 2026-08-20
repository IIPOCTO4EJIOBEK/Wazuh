@echo off
REM =====================================================================
REM  Обёртка для блокировки учётной записи Active Directory.
REM  Запускается только на агенте контроллера домена (группа dc).
REM =====================================================================
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0ahp-disable-ad-user.ps1"
exit /b %ERRORLEVEL%
