<#
    =====================================================================
     Снятие изоляции с рабочей станции Windows — вручную.

     Изоляция снимается сама по истечении timeout из ossec.conf. Этот
     сценарий нужен, когда снять её надо раньше: инцидент разобран,
     машина проверена, сотруднику надо работать.

     Запускается на самой изолированной машине от имени администратора:

         powershell -ExecutionPolicy Bypass -File .\ahp-unisolate-host.ps1

     Удаляются только правила с префиксом WAZUH-ISOLATION. Штатные
     правила межсетевого экрана и групповые политики не затрагиваются.

     Если машина изолирована и до неё не достучаться по сети, сценарий
     запускается локально или через консоль виртуальной машины на
     гипервизоре pdc-hv0.
    =====================================================================
#>

$ErrorActionPreference = 'Stop'

$LogFile    = Join-Path $env:ProgramFiles 'ossec-agent\active-response\active-responses.log'
$RulePrefix = 'WAZUH-ISOLATION'

function Write-ArLog {
    param([string]$Result, [string]$Comment = '')
    $stamp = Get-Date -Format 'yyyy/MM/dd HH:mm:ss'
    $line  = "$stamp ahp-ar: action=unisolate-manual target=$env:COMPUTERNAME rule=0 result=$Result $Comment"
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
}

# Проверка прав: без прав администратора Remove-NetFirewallRule
# завершится ошибкой уже после частичного удаления правил.
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Нужны права администратора. Запустите консоль от имени администратора.' -ForegroundColor Red
    Write-ArLog -Result 'error' -Comment 'запуск без прав администратора'
    exit 1
}

$rules = @(Get-NetFirewallRule -DisplayName "$RulePrefix-*" -ErrorAction SilentlyContinue)

if ($rules.Count -eq 0) {
    Write-Host 'Правил изоляции не найдено — машина не изолирована.' -ForegroundColor Yellow
} else {
    Write-Host "Найдено правил изоляции: $($rules.Count). Удаляю." -ForegroundColor Cyan
    $rules | Remove-NetFirewallRule
}

# Возврат политики по умолчанию: входящие блокируются, исходящие
# разрешены — это штатное состояние рабочей станции в домене.
Set-NetFirewallProfile -Profile Domain, Public, Private `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow

Write-Host 'Изоляция снята.' -ForegroundColor Green
Write-ArLog -Result 'ok' -Comment "удалено правил: $($rules.Count)"

# Проверка, что агент снова видит менеджер: без этого «снял изоляцию»
# означает лишь «удалил правила», а не «машина вернулась в работу».
Write-Host ''
Write-Host 'Проверка связи с менеджером Wazuh:' -ForegroundColor Cyan
foreach ($h in @('10.5.2.90', '10.5.2.85', '10.5.2.86')) {
    $ok = Test-NetConnection -ComputerName $h -Port 1514 -InformationLevel Quiet -WarningAction SilentlyContinue
    $mark = if ($ok) { 'доступен' } else { 'НЕДОСТУПЕН' }
    Write-Host ("  {0,-14} {1}" -f $h, $mark)
}
