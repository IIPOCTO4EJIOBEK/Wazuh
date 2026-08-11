<#
    =====================================================================
     Блокировка учётной записи Active Directory по событию безопасности.

     Запускается на агенте контроллера домена (группа агентов dc) по
     правилам 100330 и 100331. Задание приходит на стандартный ввод в
     формате active response версии 4.

     Это самое опасное из автоматических действий: ошибка означает, что
     сотрудник не может работать, а если ошибка затронет служебную
     учётную запись — встанет сервис. Поэтому предохранителей больше,
     чем самой логики:

       1. Учётные записи из защищённых групп (администраторы домена,
          предприятия, операторы) не блокируются никогда — только
          сообщение и эскалация.
       2. Точечный список неприкасаемых учётных записей.
       3. Порог на количество блокировок за час: превышение означает
          либо ошибку в правиле, либо атаку, рассчитанную на массовую
          блокировку сотрудников как способ остановить работу компании.
       4. Состав групп сохраняется в файл перед отключением, чтобы
          учётную запись можно было вернуть в исходное состояние.

     Набор защищённых групп намеренно совпадает с агентом увольнений
     (dismissal-agent/config.psd1.example): два инструмента трогают одну
     и ту же службу каталога, и расхождение в их предохранителях
     означало бы, что один разрешает то, что запрещает другой.
    =====================================================================
#>

$ErrorActionPreference = 'Stop'

$AgentRoot = Join-Path $env:ProgramFiles 'ossec-agent'
$LogFile   = Join-Path $AgentRoot 'active-response\active-responses.log'
$StateDir  = Join-Path $AgentRoot 'active-response\ahp-state'
$RateFile  = Join-Path $StateDir  'disable-rate.json'

$MaxDisablesPerHour = 3

$ProtectedGroups = @(
    'Domain Admins', 'Enterprise Admins', 'Schema Admins',
    'Administrators', 'Account Operators', 'Backup Operators',
    'Server Operators', 'Print Operators',
    'Администраторы домена', 'Администраторы предприятия',
    'Администраторы схемы', 'Администраторы'
)

$ProtectedAccounts = @(
    'Administrator', 'administrator', 'krbtgt', 'Guest',
    'svc_backup', 'svc_sdp', 'svc_1c', 'zabbix', 'bitrix'
)

function Write-ArLog {
    param([string]$Action, [string]$Target, [string]$RuleId, [string]$Result, [string]$Comment = '')
    $stamp = Get-Date -Format 'yyyy/MM/dd HH:mm:ss'
    $line  = "$stamp ahp-ar: action=$Action target=$Target rule=$RuleId result=$Result $Comment"
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
}

function Get-AlertField {
    param([object]$Json, [string[]]$Path)
    $node = $Json
    foreach ($part in $Path) {
        if ($null -eq $node) { return $null }
        $node = $node.$part
    }
    return $node
}

# Скользящее окно в час: сколько учётных записей уже отключено.
function Test-RateLimit {
    param([string]$Login)

    if (-not (Test-Path $StateDir)) {
        New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    }

    $cutoff  = (Get-Date).AddHours(-1)
    $history = @()
    if (Test-Path $RateFile) {
        try {
            $history = @(Get-Content $RateFile -Raw | ConvertFrom-Json |
                         Where-Object { [datetime]$_.time -gt $cutoff })
        } catch {
            $history = @()
        }
    }

    if ($history.Count -ge $MaxDisablesPerHour) {
        return $false
    }

    $history += [pscustomobject]@{ time = (Get-Date).ToString('o'); login = $Login }
    $history | ConvertTo-Json -Depth 3 | Set-Content -Path $RateFile -Encoding UTF8
    return $true
}

# ---------------------------------------------------------------------
# Чтение задания
# ---------------------------------------------------------------------
$raw = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($raw)) {
    Write-ArLog -Action 'disable-user' -Target 'none' -RuleId '0' -Result 'error' -Comment 'пустой ввод'
    exit 1
}

try { $msg = $raw | ConvertFrom-Json }
catch {
    Write-ArLog -Action 'disable-user' -Target 'none' -RuleId '0' -Result 'error' -Comment 'не разобран JSON'
    exit 1
}

$command = $msg.command
$ruleId  = Get-AlertField -Json $msg -Path @('parameters','alert','rule','id')
if (-not $ruleId) { $ruleId = '0' }

# Учётная запись берётся из полей события Windows. Порядок проверки
# соответствует тому, в каком поле она оказывается в наших правилах.
$login = Get-AlertField -Json $msg -Path @('parameters','alert','data','win','eventdata','subjectUserName')
if (-not $login) {
    $login = Get-AlertField -Json $msg -Path @('parameters','alert','data','win','eventdata','targetUserName')
}
if (-not $login) {
    $login = Get-AlertField -Json $msg -Path @('parameters','alert','data','dstuser')
}

if (-not $login) {
    Write-ArLog -Action 'disable-user' -Target 'none' -RuleId $ruleId -Result 'error' `
                -Comment 'в алерте нет имени учётной записи'
    exit 1
}

# Отбрасываем доменный префикс и суффикс UPN
$login = $login -replace '^.*\\', '' -replace '@.*$', ''

if ($command -ne 'add') {
    # Разблокировка автоматически не выполняется: возврат доступа —
    # решение человека после разбора инцидента.
    Write-ArLog -Action 'enable-user' -Target $login -RuleId $ruleId -Result 'skipped' `
                -Comment 'возврат доступа выполняется вручную'
    exit 0
}

# ---------------------------------------------------------------------
# Предохранители
# ---------------------------------------------------------------------
if ($ProtectedAccounts -contains $login) {
    Write-ArLog -Action 'disable-user' -Target $login -RuleId $ruleId -Result 'denied' `
                -Comment 'учётная запись в списке неприкасаемых'
    exit 0
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-ArLog -Action 'disable-user' -Target $login -RuleId $ruleId -Result 'error' `
                -Comment 'модуль ActiveDirectory недоступен'
    exit 1
}

try {
    $user = Get-ADUser -Identity $login -Properties MemberOf, DistinguishedName, Description -ErrorAction Stop
} catch {
    Write-ArLog -Action 'disable-user' -Target $login -RuleId $ruleId -Result 'error' `
                -Comment 'учётная запись не найдена в каталоге'
    exit 1
}

$groupNames = @()
foreach ($dn in $user.MemberOf) {
    try { $groupNames += (Get-ADGroup -Identity $dn).Name } catch { }
}

$hit = $groupNames | Where-Object { $ProtectedGroups -contains $_ }
if ($hit) {
    Write-ArLog -Action 'disable-user' -Target $login -RuleId $ruleId -Result 'denied' `
                -Comment "состоит в защищённой группе: $($hit -join ',') — требуется решение человека"
    exit 0
}

if (-not (Test-RateLimit -Login $login)) {
    Write-ArLog -Action 'disable-user' -Target $login -RuleId $ruleId -Result 'denied' `
                -Comment "превышен порог $MaxDisablesPerHour блокировок в час — разбор вручную"
    exit 0
}

# ---------------------------------------------------------------------
# Действие
# ---------------------------------------------------------------------
try {
    if (-not (Test-Path $StateDir)) {
        New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    }

    # Состояние до изменения — чтобы вернуть всё как было.
    $backup = [pscustomobject]@{
        login       = $login
        dn          = $user.DistinguishedName
        enabled     = (Get-ADUser -Identity $login -Properties Enabled).Enabled
        groups      = $groupNames
        description = $user.Description
        rule        = $ruleId
        time        = (Get-Date).ToString('o')
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backup | ConvertTo-Json -Depth 4 |
        Set-Content -Path (Join-Path $StateDir "$login`_$stamp.json") -Encoding UTF8

    Disable-ADAccount -Identity $login -ErrorAction Stop

    $note = "Заблокирована автоматически Wazuh по правилу $ruleId, $(Get-Date -Format 'dd.MM.yyyy HH:mm')"
    Set-ADUser -Identity $login -Description $note -ErrorAction SilentlyContinue

    Write-ArLog -Action 'disable-user' -Target $login -RuleId $ruleId -Result 'ok' `
                -Comment 'состояние сохранено для восстановления'
    exit 0
} catch {
    Write-ArLog -Action 'disable-user' -Target $login -RuleId $ruleId -Result 'error' `
                -Comment $_.Exception.Message
    exit 1
}
