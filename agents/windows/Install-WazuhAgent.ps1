<#
.SYNOPSIS
    Установка агента Wazuh на узел Windows.

.DESCRIPTION
    Рассчитан на массовую раскатку через групповую политику: скрипт
    идемпотентен, при повторном запуске на уже настроенной машине
    ничего не делает и завершается кодом 0.

    Что делает:
      1. Проверяет, не установлен ли агент нужной версии.
      2. Скачивает пакет с сетевого ресурса или из интернета.
      3. Устанавливает с параметрами регистрации (адрес менеджера,
         имя агента, группы).
      4. Дожидается подключения к менеджеру и проверяет его.
      5. Пишет результат в журнал приложений Windows — по нему видно,
         на скольких машинах политика отработала.

    Группа агента определяется автоматически по роли машины: рабочая
    станция, сервер, контроллер домена. От группы зависит набор
    собираемых журналов — см. rules/agent-groups/.

.PARAMETER Manager
    Адрес приёма агентов. По умолчанию VIP балансировщика.

.PARAMETER RegistrationPassword
    Пароль регистрации (authd). При раскатке через GPO передаётся
    из защищённого файла на сетевом ресурсе, доступном на чтение
    только компьютерам домена.

.PARAMETER Group
    Группы агента через запятую. Если не указано — определяются
    автоматически.

.EXAMPLE
    .\Install-WazuhAgent.ps1 -RegistrationPassword 'пароль'

.EXAMPLE
    .\Install-WazuhAgent.ps1 -Group 'default,windows,dc' -Force
#>

[CmdletBinding()]
param(
    [string]$Manager = '10.5.2.90',
    [string]$RegistrationPassword = '',
    [string]$PasswordFile = '\\10.2.27.118\wazuh$\authd.pass',
    [string]$Group = '',
    [string]$Version = '4.14.7',
    [string]$PackageSource = '\\10.2.27.118\wazuh$',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$EventSource = 'WazuhAgentDeploy'
$AgentDir = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
if (-not (Test-Path $AgentDir)) {
    $AgentDir = Join-Path $env:ProgramFiles 'ossec-agent'
}

# ---------------------------------------------------------------------
# Журналирование
# ---------------------------------------------------------------------
function Write-Log {
    param([string]$Message, [ValidateSet('Information','Warning','Error')][string]$Level = 'Information')

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message"

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            New-EventLog -LogName Application -Source $EventSource
        }
        $id = switch ($Level) { 'Error' { 3001 } 'Warning' { 3002 } default { 3000 } }
        Write-EventLog -LogName Application -Source $EventSource -EntryType $Level `
                       -EventId $id -Message $Message
    } catch {
        # Журнал недоступен — не повод прерывать установку
    }
}

# ---------------------------------------------------------------------
# Определение групп по роли машины
# ---------------------------------------------------------------------
function Get-AgentGroups {
    $os = Get-CimInstance Win32_OperatingSystem
    $groups = @('default', 'windows')

    switch ($os.ProductType) {
        1 { $groups += 'workstation' }        # рабочая станция
        2 { $groups += 'dc' }                 # контроллер домена
        3 {                                    # рядовой сервер
            if (Get-Service -Name 'vmms' -ErrorAction SilentlyContinue) {
                $groups += 'hyperv'
            }
            if (Get-Service -Name 'MSSQLSERVER' -ErrorAction SilentlyContinue) {
                $groups += 'mssql'
            }
        }
    }

    return ($groups -join ',')
}

# ---------------------------------------------------------------------
# Проверка текущего состояния
# ---------------------------------------------------------------------
function Get-InstalledVersion {
    $service = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
    if (-not $service) { return $null }

    $verFile = Join-Path $AgentDir 'VERSION'
    if (Test-Path $verFile) {
        return ((Get-Content $verFile -Raw).Trim() -replace '^v', '')
    }
    return 'неизвестна'
}

# ---------------------------------------------------------------------
# Основной поток
# ---------------------------------------------------------------------
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Нужны права администратора.'
    }

    $installed = Get-InstalledVersion
    if ($installed -and -not $Force) {
        if ($installed -eq $Version) {
            Write-Log "Агент версии $Version уже установлен. Ничего не делаю."
            exit 0
        }
        Write-Log "Установлена версия $installed, требуется $Version. Обновляю." -Level Warning
    }

    if (-not $Group) {
        $Group = Get-AgentGroups
    }
    Write-Log "Группы агента: $Group"

    # --- Пароль регистрации ------------------------------------------
    if (-not $RegistrationPassword) {
        if (Test-Path $PasswordFile) {
            $RegistrationPassword = (Get-Content $PasswordFile -Raw).Trim()
        } else {
            throw "Не задан пароль регистрации и недоступен $PasswordFile"
        }
    }

    # --- Пакет --------------------------------------------------------
    $msiName = "wazuh-agent-$Version-1.msi"
    $localMsi = Join-Path $env:TEMP $msiName
    $sourceMsi = Join-Path $PackageSource $msiName

    if (Test-Path $sourceMsi) {
        Write-Log "Копирую пакет с $PackageSource"
        Copy-Item -Path $sourceMsi -Destination $localMsi -Force
    } else {
        $url = "https://packages.wazuh.com/4.x/windows/$msiName"
        Write-Log "Пакет на сетевом ресурсе не найден, скачиваю с $url" -Level Warning
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $localMsi -UseBasicParsing
    }

    if (-not (Test-Path $localMsi)) {
        throw "Пакет установки не получен: $msiName"
    }

    # --- Установка ----------------------------------------------------
    # Параметры регистрации передаются в msiexec: агент регистрируется
    # сам при первом запуске службы.
    $arguments = @(
        '/i', "`"$localMsi`"",
        '/q',
        "WAZUH_MANAGER=`"$Manager`"",
        "WAZUH_REGISTRATION_SERVER=`"$Manager`"",
        "WAZUH_REGISTRATION_PASSWORD=`"$RegistrationPassword`"",
        "WAZUH_AGENT_NAME=`"$env:COMPUTERNAME`"",
        "WAZUH_AGENT_GROUP=`"$Group`"",
        'WAZUH_PROTOCOL="tcp"',
        "/l*v `"$env:TEMP\wazuh-agent-install.log`""
    )

    Write-Log "Устанавливаю агент $Version, менеджер $Manager"
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru -NoNewWindow

    if ($process.ExitCode -ne 0) {
        throw "msiexec завершился кодом $($process.ExitCode). Подробности: $env:TEMP\wazuh-agent-install.log"
    }

    Remove-Item $localMsi -Force -ErrorAction SilentlyContinue

    # --- Запуск и проверка --------------------------------------------
    Start-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
    Set-Service -Name 'WazuhSvc' -StartupType Automatic

    Write-Log 'Жду подключения к менеджеру...'
    $logFile = Join-Path $AgentDir 'ossec.log'
    $connected = $false

    for ($i = 0; $i -lt 24; $i++) {
        Start-Sleep -Seconds 5
        if (Test-Path $logFile) {
            $tail = Get-Content $logFile -Tail 60 -ErrorAction SilentlyContinue
            if ($tail -match 'Connected to the server') {
                $connected = $true
                break
            }
            if ($tail -match 'Unable to add agent|Invalid password') {
                throw 'Регистрация отклонена менеджером: неверный пароль или имя агента занято.'
            }
        }
    }

    if ($connected) {
        Write-Log "Агент установлен и подключён к $Manager. Группы: $Group"
        exit 0
    }

    Write-Log "Агент установлен, но подключение к $Manager за 2 минуты не подтверждено. Проверить доступность портов 1514 и 1515." -Level Warning
    exit 0

} catch {
    Write-Log "Установка не удалась: $($_.Exception.Message)" -Level Error
    exit 1
}
