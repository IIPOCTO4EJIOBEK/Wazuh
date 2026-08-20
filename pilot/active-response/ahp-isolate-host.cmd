@echo off
REM =====================================================================
REM  Обёртка для запуска изоляции узла из wazuh-execd.
REM
REM  Агент Windows запускает active response как исполняемый файл и
REM  передаёт задание на стандартный ввод. PowerShell-сценарий напрямую
REM  запустить нельзя, поэтому нужен .cmd: он наследует стандартный
REM  ввод, и сценарий читает задание через [Console]::In.ReadToEnd().
REM
REM  -ExecutionPolicy Bypass обязателен: политика выполнения в домене
REM  может запрещать неподписанные сценарии, а active response должен
REM  срабатывать независимо от неё.
REM =====================================================================
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0ahp-isolate-host.ps1"
exit /b %ERRORLEVEL%
