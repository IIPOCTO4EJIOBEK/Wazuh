<#
    =====================================================================
     Изоляция рабочей станции Windows.

     Вызывается wazuh-execd через обёртку ahp-isolate-host.cmd. На
     стандартный ввод приходит JSON протокола active response версии 4.

     Что делает изоляция: включает межсетевой экран Windows во всех
     профилях, блокирует весь входящий и исходящий трафик и оставляет
     ровно два исключения — менеджеры Wazuh и контроллеры домена.

     Почему именно так:
       * связь с менеджером нужна, иначе изолированную машину нельзя
         будет разблокировать удалённо, и придётся идти ногами;
       * связь с контроллером домена нужна, иначе после перезагрузки
         никто не сможет войти под доменной учётной записью, включая
         администратора, который приедет разбираться;
       * правила помечены общим префиксом WAZUH-ISOLATION, поэтому
         снятие изоляции удаляет ровно их и не трогает штатные политики.

     Возврат в обычный режим: ahp-unisolate-host.ps1, либо автоматически
     по истечении timeout из ossec.conf (wazuh-execd вызывает этот же
     скрипт с command=delete).
    =====================================================================
#>

$ErrorActionPreference = 'Stop'

$LogFile   = Join-Path $env:ProgramFiles 'ossec-agent\active-response\active-responses.log'
$RulePrefix = 'WAZUH-ISOLATION'

# Адреса, до которых доступ сохраняется. Заполняется при развёртывании
# (roles/wazuh_manager/tasks/content.yml подставляет реальные значения
# в шаблон, здесь — значения по умолчанию для нашей сети).
$AllowedHosts = @(
    '10.5.2.85',   # wazuh-mgr-01
    '10.5.2.86',   # wazuh-mgr-02
    '10.5.2.90',   # VIP приёма агентов
    '10.1.20.41',  # PDC-DB1 / контроллер домена и DNS
    '10.2.27.118'  # pdc-hv0, гипервизор
)

function Write-ArLog {
    param(
        [string]$Action,
        [string]$Target,
        [string]$RuleId,
        [string]$Result,
        [string]$Comment = ''
    )
    $stamp = Get-Date -Format 'yyyy/MM/dd HH:mm:ss'
    $line  = "$stamp ahp-ar: action=$Action target=$Target rule=$RuleId result=$Result $Comment"
    try {
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch {
        # Если журнал недоступен, изоляцию всё равно выполняем:
        # потерянная запись хуже, чем незаблокированная машина, но
        # не настолько, чтобы отказываться от действия.
    }
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

# ---------------------------------------------------------------------
# Чтение задания
# ---------------------------------------------------------------------
$raw = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($raw)) {
    Write-ArLog -Action 'isolate' -Target $env:COMPUTERNAME -RuleId '0' -Result 'error' -Comment 'пустой ввод'
    exit 1
}

try {
    $msg = $raw | ConvertFrom-Json
} catch {
    Write-ArLog -Action 'isolate' -Target $env:COMPUTERNAME -RuleId '0' -Result 'error' -Comment 'не разобран JSON'
    exit 1
}

$command = $msg.command
$ruleId  = Get-AlertField -Json $msg -Path @('parameters', 'alert', 'rule', 'id')
if (-not $ruleId) { $ruleId = '0' }

# ---------------------------------------------------------------------
# Предохранитель: контроллеры домена и серверы не изолируются никогда.
# Изоляция контроллера домена останавливает работу всей компании —
# это дороже любого вредоноса на одной машине.
# ---------------------------------------------------------------------
$productType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
if ($productType -ne 1) {
    Write-ArLog -Action 'isolate' -Target $env:COMPUTERNAME -RuleId $ruleId `
                -Result 'skipped-allowlist' -Comment 'узел является сервером или контроллером домена'
    exit 0
}

switch ($command) {

    'add' {
        try {
            # Профили межсетевого экрана включаются принудительно:
            # вредонос мог их отключить до срабатывания правила.
            Set-NetFirewallProfile -Profile Domain, Public, Private `
                -Enabled True `
                -DefaultInboundAction Block `
                -DefaultOutboundAction Block

            foreach ($h in $AllowedHosts) {
                New-NetFirewallRule -DisplayName "$RulePrefix-out-$h" `
                    -Direction Outbound -Action Allow -RemoteAddress $h `
                    -Profile Any -Enabled True | Out-Null

                New-NetFirewallRule -DisplayName "$RulePrefix-in-$h" `
                    -Direction Inbound -Action Allow -RemoteAddress $h `
                    -Profile Any -Enabled True | Out-Null
            }

            # DNS и DHCP до разрешённых узлов: без разрешения имён
            # агент не найдёт менеджер после перезапуска сети.
            New-NetFirewallRule -DisplayName "$RulePrefix-out-dns" `
                -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 `
                -RemoteAddress $AllowedHosts -Profile Any -Enabled True | Out-Null

            Write-ArLog -Action 'isolate' -Target $env:COMPUTERNAME -RuleId $ruleId -Result 'ok' `
                        -Comment "разрешены только $($AllowedHosts -join ',')"
            exit 0
        } catch {
            Write-ArLog -Action 'isolate' -Target $env:COMPUTERNAME -RuleId $ruleId `
                        -Result 'error' -Comment $_.Exception.Message
            exit 1
        }
    }

    'delete' {
        try {
            Get-NetFirewallRule -DisplayName "$RulePrefix-*" -ErrorAction SilentlyContinue |
                Remove-NetFirewallRule

            Set-NetFirewallProfile -Profile Domain, Public, Private `
                -DefaultInboundAction Block `
                -DefaultOutboundAction Allow

            Write-ArLog -Action 'unisolate' -Target $env:COMPUTERNAME -RuleId $ruleId -Result 'ok'
            exit 0
        } catch {
            Write-ArLog -Action 'unisolate' -Target $env:COMPUTERNAME -RuleId $ruleId `
                        -Result 'error' -Comment $_.Exception.Message
            exit 1
        }
    }

    default {
        Write-ArLog -Action 'isolate' -Target $env:COMPUTERNAME -RuleId $ruleId `
                    -Result 'error' -Comment "неизвестная команда: $command"
        exit 1
    }
}
