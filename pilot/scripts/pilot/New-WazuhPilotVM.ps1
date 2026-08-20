<#
.SYNOPSIS
    Создание виртуальной машины пилота Wazuh на Hyper-V.

.DESCRIPTION
    Создаёт машину с параметрами, подобранными под задачу, и снимает
    четыре настройки Hyper-V по умолчанию, которые здесь мешают:

      1. Динамическая память — несовместима с кучей JVM: гипервизор
         отбирает страницы, которые машина считает своими, и сборка
         мусора начинает работать с диском.
      2. Шаблон Secure Boot по умолчанию — с ним Ubuntu не загрузится.
      3. Автоматические контрольные точки — включены по умолчанию в
         Windows Server 2019 и новее, заметно замедляют диск.
      4. Синхронизация времени от гипервизора — конфликтует с NTP
         домена, а расхождение часов ломает корреляцию событий.

    Скрипт идемпотентен: если машина с таким именем уже есть, он
    ничего не пересоздаёт, а сообщает об этом.

.PARAMETER Name
    Имя виртуальной машины. По умолчанию wazuh-pilot.

.PARAMETER SwitchName
    Виртуальный коммутатор серверной сети.

.PARAMETER Path
    Том, где размещаются машины и диски.

.PARAMETER IsoPath
    Установочный образ Ubuntu Server 24.04 LTS.

.EXAMPLE
    .\New-WazuhPilotVM.ps1 -SwitchName "SET-Wazuh" -Path "D:\Hyper-V" `
                           -IsoPath "D:\ISO\ubuntu-24.04-live-server-amd64.iso"

.EXAMPLE
    # Отказоустойчивая схема: узел индексера с диском на 1 ТБ
    .\New-WazuhPilotVM.ps1 -Name wazuh-idx-01 -MemoryGB 16 -CpuCount 8 `
                           -IndexerDiskGB 1024 -SwitchName "SET-Wazuh" `
                           -Path "D:\Hyper-V" -IsoPath "D:\ISO\ubuntu.iso"
#>

[CmdletBinding()]
param(
    [string]$Name          = "wazuh-pilot",
    [Parameter(Mandatory)] [string]$SwitchName,
    [Parameter(Mandatory)] [string]$Path,
    [Parameter(Mandatory)] [string]$IsoPath,

    [int]$CpuCount         = 8,
    [int]$MemoryGB         = 16,
    [int]$SystemDiskGB     = 60,
    [int]$IndexerDiskGB    = 250,
    [int]$OssecDiskGB      = 100,

    [int]$StartDelaySeconds = 120,
    [switch]$StartAfterCreate
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$Text) Write-Host "`n$Text" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Text) Write-Host "  [ок] $Text" -ForegroundColor Green }
function Write-Warn { param([string]$Text) Write-Host "  [!]  $Text" -ForegroundColor Yellow }

# ---------------------------------------------------------------------
Write-Step "Проверки"
# ---------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
    throw "Модуль Hyper-V недоступен. Скрипт запускается на самом гипервизоре."
}

if (Get-VM -Name $Name -ErrorAction SilentlyContinue) {
    Write-Warn "Машина '$Name' уже существует — ничего не меняю."
    Get-VM -Name $Name | Format-List Name, State, ProcessorCount,
        @{n='ОЗУ, ГБ'; e={[int]($_.MemoryStartup / 1GB)}}
    return
}

if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    throw "Виртуальный коммутатор '$SwitchName' не найден. Доступны: " +
          ((Get-VMSwitch | Select-Object -ExpandProperty Name) -join ', ')
}

if (-not (Test-Path $IsoPath)) {
    throw "Установочный образ не найден: $IsoPath"
}

$vmPath = Join-Path $Path $Name
$freeGB = [int]((Get-PSDrive -Name (Split-Path $Path -Qualifier).TrimEnd(':')).Free / 1GB)
$needGB = $SystemDiskGB + $IndexerDiskGB + $OssecDiskGB

if ($freeGB -lt 80) {
    throw "На томе $Path свободно $freeGB ГБ — недостаточно даже под систему."
}
if ($freeGB -lt $needGB) {
    Write-Warn "Свободно $freeGB ГБ, при полном заполнении дисков нужно $needGB ГБ."
    Write-Warn "Диски динамические, места хватит на старте, но следите за томом."
} else {
    Write-Ok "Места на $Path достаточно: $freeGB ГБ"
}

# ---------------------------------------------------------------------
Write-Step "Создание машины $Name"
# ---------------------------------------------------------------------
$vm = New-VM -Name $Name -Generation 2 `
             -MemoryStartupBytes ($MemoryGB * 1GB) `
             -NewVHDPath (Join-Path $vmPath "$Name-os.vhdx") `
             -NewVHDSizeBytes ($SystemDiskGB * 1GB) `
             -SwitchName $SwitchName `
             -Path $Path
Write-Ok "Машина создана, системный диск $SystemDiskGB ГБ"

# Память фиксированная — см. пояснение в заголовке
Set-VMMemory  -VMName $Name -DynamicMemoryEnabled $false -StartupBytes ($MemoryGB * 1GB)
Set-VMProcessor -VMName $Name -Count $CpuCount
Write-Ok "$CpuCount vCPU, $MemoryGB ГБ фиксированной памяти"

# ---------------------------------------------------------------------
Write-Step "Отдельные тома под данные"
# ---------------------------------------------------------------------
# Индексер и менеджер живут на своих дисках: переполнение индексами на
# системном томе останавливает всю операционную систему.
$disks = @(
    @{ Name = "$Name-indexer.vhdx"; SizeGB = $IndexerDiskGB; Role = "индексы событий" },
    @{ Name = "$Name-ossec.vhdx";   SizeGB = $OssecDiskGB;   Role = "менеджер и буфер" }
)

foreach ($d in $disks) {
    $vhd = Join-Path $vmPath $d.Name
    New-VHD -Path $vhd -SizeBytes ($d.SizeGB * 1GB) -Dynamic | Out-Null
    Add-VMHardDiskDrive -VMName $Name -Path $vhd -ControllerType SCSI
    Write-Ok "$($d.Name) — $($d.SizeGB) ГБ, $($d.Role)"
}

# ---------------------------------------------------------------------
Write-Step "Поправки к значениям Hyper-V по умолчанию"
# ---------------------------------------------------------------------
Set-VMFirmware -VMName $Name -SecureBootTemplate MicrosoftUEFICertificateAuthority
Write-Ok "Secure Boot переведён на шаблон для UEFI Linux"

Set-VM -Name $Name -AutomaticCheckpointsEnabled $false
Write-Ok "Автоматические контрольные точки отключены"

Disable-VMIntegrationService -VMName $Name -Name "Time Synchronization"
Write-Ok "Синхронизация времени от гипервизора отключена"

Set-VM -Name $Name -AutomaticStartAction Start `
                   -AutomaticStartDelay $StartDelaySeconds `
                   -AutomaticStopAction ShutDown
Write-Ok "Автозапуск с задержкой $StartDelaySeconds с, корректное выключение"

# ---------------------------------------------------------------------
Write-Step "Установочный образ"
# ---------------------------------------------------------------------
Add-VMDvdDrive -VMName $Name -Path $IsoPath
Set-VMFirmware -VMName $Name -FirstBootDevice (Get-VMDvdDrive -VMName $Name)
Write-Ok "Загрузка с $([System.IO.Path]::GetFileName($IsoPath))"

# ---------------------------------------------------------------------
Write-Step "Готово"
# ---------------------------------------------------------------------
Get-VM -Name $Name | Format-List Name, State, ProcessorCount,
    @{n='ОЗУ, ГБ';       e={[int]($_.MemoryStartup / 1GB)}},
    @{n='Динамическая';  e={$_.DynamicMemoryEnabled}},
    @{n='Контр. точки';  e={$_.AutomaticCheckpointsEnabled}}

Write-Host @"

  Дальше:

  1. Установить Ubuntu Server 24.04 LTS — размечать только системный диск.
  2. После установки, на самой машине от root:

       ./prepare-ubuntu-node.sh --indexer-disk /dev/sdb \
                                --ossec-disk   /dev/sdc \
                                --ssh-key      "<открытый ключ ansible>" \
                                --hostname     $Name \
                                --ntp          <адрес NTP домена>

  3. Развернуть платформу с управляющей машины:

       ansible-playbook -i inventory/pilot/hosts.yml site.yml --ask-vault-pass

"@ -ForegroundColor Gray

if ($StartAfterCreate) {
    Start-VM -Name $Name
    Write-Ok "Машина запущена — подключитесь консолью для установки ОС"
} else {
    Write-Warn "Машина не запущена. Запустить: Start-VM -Name $Name"
}
