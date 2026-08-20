<#
.SYNOPSIS
    Включение расширенного аудита на контроллере домена.

.DESCRIPTION
    Без этих политик события 4688, 4769 и 4104 не создаются вовсе, и
    собирать будет нечего — каким бы способом события ни доставлялись
    в Wazuh. Это первое, что делается при подключении Active Directory,
    и оно не зависит от готовности сервера Wazuh.

    Скрипт настраивает:
      * подкатегории расширенного аудита (auditpol);
      * запись командной строки в событие 4688 — без неё видно имя
        процесса, но не аргументы, и правила на обфусцированный
        PowerShell и удаление теневых копий бесполезны;
      * запись блоков сценариев PowerShell (события 4103 и 4104);
      * размер журнала безопасности — на контроллере домена журнал по
        умолчанию перекрывается за часы, и события пропадают раньше,
        чем их успевают забрать.

    Применяется немедленно и на пилоте из двух контроллеров этого
    достаточно. Для постоянного режима те же параметры задаются
    групповой политикой Default Domain Controllers Policy — иначе
    следующее применение политики их перезапишет. Состав политик для
    ручного переноса выводится ключом -ShowGpoSettings.

.PARAMETER WhatIf
    Показать, что было бы изменено, ничего не меняя.

.PARAMETER VerifyOnly
    Только проверить текущее состояние.

.PARAMETER SecurityLogSizeMB
    Размер журнала безопасности. По умолчанию 1024 МБ.

.EXAMPLE
    .\Enable-AdAuditPolicy.ps1 -VerifyOnly

.EXAMPLE
    .\Enable-AdAuditPolicy.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$VerifyOnly,
    [switch]$ShowGpoSettings,
    [int]$SecurityLogSizeMB = 1024
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$T) Write-Host "`n$T" -ForegroundColor Cyan }
function Write-Ok   { param([string]$T) Write-Host "  [ок]     $T" -ForegroundColor Green }
function Write-No   { param([string]$T) Write-Host "  [нет]    $T" -ForegroundColor Red }
function Write-Warn { param([string]$T) Write-Host "  [!]      $T" -ForegroundColor Yellow }

# Подкатегории и режим. Имена задаются по идентификатору GUID, а не по
# названию: названия локализованы, и на русской системе поиск по
# английскому имени не сработает.
$Subcategories = @(
    @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Вход в систему';                      Mode = 'enable:success,failure' }
    @{ Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Name = 'Выход из системы';                    Mode = 'enable:success'         }
    @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Name = 'Блокировка учётной записи';           Mode = 'enable:success,failure' }
    @{ Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Name = 'Специальный вход';                    Mode = 'enable:success'         }
    @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Name = 'Создание процесса';                   Mode = 'enable:success'         }
    @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'Управление учётными записями';        Mode = 'enable:success,failure' }
    @{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Name = 'Управление группами безопасности';    Mode = 'enable:success,failure' }
    @{ Guid = '{0CCE923B-69AE-11D9-BED3-505054503030}'; Name = 'Доступ к службе каталогов';           Mode = 'enable:success,failure' }
    @{ Guid = '{0CCE923C-69AE-11D9-BED3-505054503030}'; Name = 'Изменения службы каталогов';          Mode = 'enable:success'         }
    @{ Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Name = 'Проверка учётных данных';             Mode = 'enable:success,failure' }
    @{ Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Name = 'Операции с билетами Kerberos';        Mode = 'enable:success,failure' }
    @{ Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Name = 'Проверка подлинности Kerberos';       Mode = 'enable:success,failure' }
    @{ Guid = '{0CCE9220-69AE-11D9-BED3-505054503030}'; Name = 'Доступ к объектам ядра';              Mode = 'enable:success,failure' }
    @{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Name = 'Изменение политики аудита';           Mode = 'enable:success,failure' }
)

$RegistrySettings = @(
    @{
        # Без этого параметра расширенные подкатегории аудита, заданные
        # выше, может перекрыть устаревшая политика категорий — и тогда
        # часть событий тихо перестанет писаться. Проверка CIS 2.3.2.1
        # на пилоте эту настройку не нашла ни на одном узле.
        Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name  = 'SCENoApplyLegacyAuditPolicy'
        Value = 1
        Why   = 'подкатегории аудита не перекрываются устаревшей политикой'
    }
    @{
        Path  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        Name  = 'ProcessCreationIncludeCmdLine_Enabled'
        Value = 1
        Why   = 'командная строка в событии 4688'
    }
    @{
        Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        Name  = 'EnableScriptBlockLogging'
        Value = 1
        Why   = 'запись блоков PowerShell, события 4104'
    }
    @{
        Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
        Name  = 'EnableModuleLogging'
        Value = 1
        Why   = 'запись вызовов модулей PowerShell, события 4103'
    }
)

# ---------------------------------------------------------------------
if ($ShowGpoSettings) {
    Write-Host @"

Что задать групповой политикой Default Domain Controllers Policy,
чтобы настройки пережили следующее применение политики.

Конфигурация компьютера → Политики → Конфигурация Windows →
  Параметры безопасности → Расширенная настройка политики аудита:

$( ($Subcategories | ForEach-Object { "    {0,-42} {1}" -f $_.Name, $_.Mode }) -join "`n" )

    Локальные политики → Параметры безопасности →
        Аудит: принудительно переопределять параметры категории
        параметрами подкатегории                          = Включено

Конфигурация компьютера → Административные шаблоны:

    Система → Аудит создания процессов →
        Включать командную строку в события создания процессов = Включено

    Компоненты Windows → Windows PowerShell →
        Включить регистрацию блоков сценариев = Включено
        Включить регистрацию модулей          = Включено

Конфигурация компьютера → Политики → Конфигурация Windows →
  Параметры безопасности → Журнал событий:

    Максимальный размер журнала безопасности = $($SecurityLogSizeMB * 1024) КБ

"@ -ForegroundColor Gray
    return
}

# ---------------------------------------------------------------------
Write-Step "Проверка окружения"
# ---------------------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Нужны права администратора. Запустите консоль от имени администратора."
}

$productType = (Get-CimInstance Win32_OperatingSystem).ProductType
if ($productType -ne 2) {
    Write-Warn "Узел не является контроллером домена (ProductType=$productType)."
    Write-Warn "Скрипт рассчитан на контроллеры; на рядовом сервере часть подкатегорий бессмысленна."
}
Write-Ok "$env:COMPUTERNAME, $((Get-CimInstance Win32_OperatingSystem).Caption)"

# ---------------------------------------------------------------------
Write-Step "Подкатегории аудита"
# ---------------------------------------------------------------------
$applied = 0
foreach ($sub in $Subcategories) {
    $current = (auditpol /get /subcategory:"$($sub.Guid)" /r 2>$null | ConvertFrom-Csv)
    $now     = if ($current) { $current.'Inclusion Setting' } else { 'неизвестно' }

    if ($VerifyOnly) {
        if ($now -match 'Success|Failure|Успех|Отказ') { Write-Ok "$($sub.Name): $now" }
        else { Write-No "$($sub.Name): $now" }
        continue
    }

    $modeSpec = $sub.Mode -replace '^enable:', ''
    $success  = if ($modeSpec -match 'success') { 'enable' } else { 'disable' }
    $failure  = if ($modeSpec -match 'failure') { 'enable' } else { 'disable' }

    if ($PSCmdlet.ShouldProcess($sub.Name, "auditpol /set")) {
        $null = auditpol /set /subcategory:"$($sub.Guid)" /success:$success /failure:$failure 2>&1

        # Читаем обратно: при неверном идентификаторе auditpol не всегда
        # возвращает ошибку, но и не применяет ничего — это надо увидеть
        $after = (auditpol /get /subcategory:"$($sub.Guid)" /r 2>$null | ConvertFrom-Csv)
        if ($LASTEXITCODE -eq 0 -and $after -and
            $after.'Inclusion Setting' -match 'Success|Failure|Успех|Отказ') {
            Write-Ok "$($sub.Name) → $($after.'Inclusion Setting')"
            $applied++
        } else {
            Write-No "$($sub.Name): не применилось — проверьте идентификатор подкатегории"
        }
    }
}

# ---------------------------------------------------------------------
Write-Step "Параметры реестра"
# ---------------------------------------------------------------------
foreach ($r in $RegistrySettings) {
    $current = (Get-ItemProperty -Path $r.Path -Name $r.Name -ErrorAction SilentlyContinue).($r.Name)

    if ($VerifyOnly) {
        if ($current -eq $r.Value) { Write-Ok "$($r.Why): включено" }
        else { Write-No "$($r.Why): выключено (значение: $current)" }
        continue
    }

    if ($current -eq $r.Value) { Write-Ok "$($r.Why): уже включено"; continue }

    if ($PSCmdlet.ShouldProcess($r.Why, "установить $($r.Name)=$($r.Value)")) {
        if (-not (Test-Path $r.Path)) { New-Item -Path $r.Path -Force | Out-Null }
        Set-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Value -Type DWord
        Write-Ok "$($r.Why): включено"
    }
}

# ---------------------------------------------------------------------
Write-Step "Размер журнала безопасности"
# ---------------------------------------------------------------------
# На контроллере домена журнал по умолчанию перекрывается за часы.
# События пропадают раньше, чем их успевает забрать агент после
# любого перерыва в связи.
$log = Get-WinEvent -ListLog Security
$currentMB = [int]($log.MaximumSizeInBytes / 1MB)

if ($VerifyOnly) {
    if ($currentMB -ge $SecurityLogSizeMB) { Write-Ok "журнал безопасности: $currentMB МБ" }
    else { Write-No "журнал безопасности: $currentMB МБ, рекомендуется $SecurityLogSizeMB МБ" }
} elseif ($currentMB -lt $SecurityLogSizeMB) {
    if ($PSCmdlet.ShouldProcess("журнал Security", "увеличить до $SecurityLogSizeMB МБ")) {
        wevtutil sl Security /ms:($SecurityLogSizeMB * 1MB)
        Write-Ok "журнал безопасности увеличен до $SecurityLogSizeMB МБ"
    }
} else {
    Write-Ok "журнал безопасности: $currentMB МБ, менять не нужно"
}

# ---------------------------------------------------------------------
Write-Step "Итог"
# ---------------------------------------------------------------------
if ($VerifyOnly) {
    Write-Host "`n  Проверка завершена. Строки [нет] — то, что надо включить.`n"
    return
}

Write-Host @"

  Применено подкатегорий: $applied

  ВАЖНО: параметры заданы локально и действуют немедленно, но следующее
  применение групповой политики может их перезаписать. Для постоянного
  режима перенесите их в Default Domain Controllers Policy:

      .\Enable-AdAuditPolicy.ps1 -ShowGpoSettings

  Проверить, что события пошли (через 5-10 минут):

      Get-WinEvent -LogName Security -MaxEvents 20 |
          Where-Object Id -in 4624,4625,4688 |
          Select-Object TimeCreated, Id, @{n='Кто';e={`$_.Properties[5].Value}}

      Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 5 |
          Where-Object Id -eq 4104

  Полная проверка состояния:

      .\Enable-AdAuditPolicy.ps1 -VerifyOnly

"@ -ForegroundColor Gray
