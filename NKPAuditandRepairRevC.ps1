#requires -Version 7.0
<#
.SYNOPSIS
Revision C. Audits and optionally repairs vSphere Native Key Provider host configuration, then creates an Excel workbook with provider, host, key, and object usage tabs.

.Author
Michael Molle

.DESCRIPTION
The script inventories Native Key Providers, ESXi host crypto state and host runtime keys, VM home keys,
virtual disk keys, and keys returned by the vCenter CryptoManager. With -Remediate, eligible noncompliant
hosts are assigned the selected NKP using Set-VMHost -KeyProvider. All eligible hosts are processed without
per-host prompts by default, followed by one propagation wait and a verification pass.

The workbook includes target and optional source-vCenter key inventory, destination key availability, HCX readiness evidence, host status, provider events, and errors. CSV copies are
also written to a companion directory. No plaintext cryptographic key material is read or exported.

.EXAMPLE
./NKPAuditandRepairRevC.ps1 -vCenter vcsa01.example.com -InstallPrerequisites

.EXAMPLE
./NKPAuditandRepairRevC.ps1 -vCenter vcsa01.example.com -Cluster Cluster01 -KeyProvider DEV1 -Remediate -PropagationSeconds 300

.EXAMPLE
./NKPAuditandRepairRevC.ps1 -vCenter vcsa01.example.com -Cluster Cluster01 -KeyProvider DEV1 -Remediate -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$vCenter,
    [pscredential]$Credential,
    [string[]]$Cluster,
    [string[]]$KeyProvider,
    [switch]$Remediate,
    [ValidateRange(0, 1800)][int]$PropagationSeconds = 300,
    [string]$OutputPath = (Join-Path (Get-Location) ('NKP-Audit-{0}-{1}.xlsx' -f ($vCenter -replace '[^A-Za-z0-9._-]', '_'), (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [switch]$InstallPrerequisites,
    [switch]$IgnoreInvalidCertificate,
    [switch]$KeepConnected,
    [ValidateRange(1, 3650)][int]$RecentKeyDays = 30,
    [ValidateRange(1, 3650)][int]$EventLookbackDays = 90,
    [string]$KeyHistoryPath,
    [ValidateRange(100, 100000)][int]$EventMaxSamples = 5000,
    [switch]$DeepEventScan,
    [switch]$SkipEventHistory,
    [string]$LogPath,
    [string]$SourceVCenter,
    [pscredential]$SourceCredential,
    [switch]$RefreshSafeHosts,
    [switch]$IncludeHCXReadiness,
    [string[]]$HCXVMName,
    [string]$EncryptionStoragePolicyName
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$connected = $false
$sourceConnected = $false
$script:viServer = $null
$script:sourceViServer = $null
$runStartedUtc = (Get-Date).ToUniversalTime()
if ([string]::IsNullOrWhiteSpace($KeyHistoryPath)) {
    $historyParent = Split-Path -Parent $OutputPath
    if (-not $historyParent) { $historyParent = (Get-Location).Path }
    $KeyHistoryPath = Join-Path $historyParent ('NKP-Key-History-{0}.json' -f ($vCenter -replace '[^A-Za-z0-9._-]', '_'))
}
if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $logParent = Split-Path -Parent $OutputPath
    if (-not $logParent) { $logParent = (Get-Location).Path }
    $LogPath = Join-Path $logParent ('NKP-Audit-{0}-{1}.log' -f ($vCenter -replace '[^A-Za-z0-9._-]', '_'), (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$logDirectory = Split-Path -Parent $LogPath
if ($logDirectory -and -not (Test-Path -LiteralPath $logDirectory)) { New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null }
function Write-RunLog {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -LiteralPath $LogPath -Value $line -Encoding utf8
    Write-Host $line -ForegroundColor $(if ($Level -eq 'ERROR') { 'Red' } elseif ($Level -eq 'WARN') { 'Yellow' } else { 'Cyan' })
}
Write-RunLog "Starting NKP audit. Output=$OutputPath; Log=$LogPath"

$providersReport = [System.Collections.Generic.List[object]]::new()
$hostReport = [System.Collections.Generic.List[object]]::new()
$keyUsageReport = [System.Collections.Generic.List[object]]::new()
$allKeysReport = [System.Collections.Generic.List[object]]::new()
$errorReport = [System.Collections.Generic.List[object]]::new()
$providerEventReport = [System.Collections.Generic.List[object]]::new()
$sourceKeyUsageReport = [System.Collections.Generic.List[object]]::new()
$vCenterKeyStatusReport = [System.Collections.Generic.List[object]]::new()
$hcxReadinessReport = [System.Collections.Generic.List[object]]::new()
$sourceProviderReport = [System.Collections.Generic.List[object]]::new()
$clusterReadinessReport = [System.Collections.Generic.List[object]]::new()
$storagePolicyReport = [System.Collections.Generic.List[object]]::new()

function Get-FirstValue {
    param([AllowNull()]$InputObject, [Parameter(Mandatory)][string[]]$Name, $Default = $null)
    if ($null -eq $InputObject) { return $Default }
    foreach ($item in $Name) {
        $property = $InputObject.PSObject.Properties[$item]
        if ($property -and $null -ne $property.Value) { return $property.Value }
    }
    return $Default
}

function ConvertTo-KeyIdentity {
    param([AllowNull()]$Key)
    if ($null -eq $Key) { return [pscustomobject]@{ KeyId = ''; ProviderId = '' } }
    $keyId = Get-FirstValue $Key @('KeyId', 'Id')
    $providerId = Get-FirstValue $Key @('ProviderId', 'KeyProviderId')
    if ($keyId -and $keyId.PSObject.Properties['KeyId']) {
        $providerId = Get-FirstValue $keyId @('ProviderId', 'KeyProviderId') $providerId
        $keyId = $keyId.KeyId
    }
    if ($providerId -and $providerId.PSObject.Properties['Id']) { $providerId = $providerId.Id }
    [pscustomobject]@{ KeyId = [string]$keyId; ProviderId = [string]$providerId }
}

function Get-ProviderId {
    param([Parameter(Mandatory)]$Provider)
    $value = [string](Get-FirstValue $Provider @('Id', 'KeyProviderId', 'ProviderId'))
    if ([string]::IsNullOrWhiteSpace($value)) { $value = [string]$Provider.Name }
    return $value
}

function Get-ProviderName {
    param([string]$ProviderId)
    if ([string]::IsNullOrWhiteSpace($ProviderId)) { return '' }
    $match = $script:selectedProviders | Where-Object { (Get-ProviderId $_) -ieq $ProviderId } | Select-Object -First 1
    if ($match) { return [string]$match.Name }
    return '(provider not returned by filter)'
}

function Add-ErrorRecord {
    param([string]$Stage, [string]$ObjectType, [string]$ObjectName, [string]$Message)
    $errorReport.Add([pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        Stage = $Stage; ObjectType = $ObjectType; ObjectName = $ObjectName; Message = $Message
    })
}

function Get-HostCacheKeys {
    param([Parameter(Mandatory)]$VMHost)
    $managerId = $VMHost.ExtensionData.ConfigManager.CryptoManager
    if (-not $managerId) { throw 'Host ConfigManager does not expose a CryptoManager.' }
    $manager = Get-View -Id $managerId -Server $script:viServer -ErrorAction Stop
    @($manager.ListKeys(0) | ForEach-Object { ConvertTo-KeyIdentity $_ })
}

function Get-HostSnapshot {
    param([Parameter(Mandatory)]$VMHost, [Parameter(Mandatory)]$Provider)
    $providerId = Get-ProviderId $Provider
    $cacheKeys = @()
    $readError = ''
    try { $cacheKeys = @(Get-HostCacheKeys $VMHost) } catch { $readError = $_.Exception.Message }
    $runtimeKey = ConvertTo-KeyIdentity $VMHost.ExtensionData.Runtime.CryptoKeyId
    $cryptoState = [string]$VMHost.ExtensionData.Runtime.CryptoState
    $reachable = $VMHost.ConnectionState -eq 'Connected' -and $VMHost.PowerState -eq 'PoweredOn'
    $runtimeProviderMatch = -not [string]::IsNullOrWhiteSpace($runtimeKey.ProviderId) -and $runtimeKey.ProviderId -ieq $providerId
    $cacheMatchCount = @($cacheKeys | Where-Object { $_.ProviderId -ieq $providerId }).Count
    [pscustomobject]@{
        CryptoState = $cryptoState
        RuntimeKeyId = $runtimeKey.KeyId
        RuntimeProviderId = $runtimeKey.ProviderId
        RuntimeProviderName = Get-ProviderName $runtimeKey.ProviderId
        HostCacheKeyCount = $cacheKeys.Count
        ProviderCacheKeyCount = $cacheMatchCount
        ProviderObserved = [bool]($runtimeProviderMatch -or $cacheMatchCount -gt 0)
        Reachable = $reachable
        ReadError = $readError
        Compliant = [bool]($reachable -and $cryptoState -eq 'safe' -and -not $readError)
        CacheKeys = $cacheKeys
    }
}

function Add-KeyUsage {
    param(
        [string]$Source, [string]$KeyId, [string]$ProviderId, [string]$UsageType,
        [string]$ObjectType, [string]$ObjectName, [string]$Datacenter,
        [string]$ClusterName, [string]$HostName, [string]$VMName,
        [string]$Device, [string]$Details
    )
    if ([string]::IsNullOrWhiteSpace($KeyId) -and [string]::IsNullOrWhiteSpace($ProviderId)) { return }
    $keyUsageReport.Add([pscustomobject]@{
        Source = $Source; KeyId = $KeyId; ProviderId = $ProviderId; ProviderName = Get-ProviderName $ProviderId
        UsageType = $UsageType; ObjectType = $ObjectType; ObjectName = $ObjectName
        Datacenter = $Datacenter; Cluster = $ClusterName; Host = $HostName; VM = $VMName
        Device = $Device; Details = $Details
    })
}

function Export-WorkbookAndCsv {
    $base = [IO.Path]::GetFileNameWithoutExtension($OutputPath)
    $parent = Split-Path -Parent $OutputPath
    if (-not $parent) { $parent = (Get-Location).Path }
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $csvDirectory = Join-Path $parent ($base + '-CSV')
    New-Item -ItemType Directory -Path $csvDirectory -Force | Out-Null

    $summary = @(
        [pscustomobject]@{ Metric = 'vCenter'; Value = $vCenter }
        [pscustomobject]@{ Metric = 'Run started UTC'; Value = $runStartedUtc.ToString('o') }
        [pscustomobject]@{ Metric = 'Run completed UTC'; Value = (Get-Date).ToUniversalTime().ToString('o') }
        [pscustomobject]@{ Metric = 'Native key providers'; Value = $providersReport.Count }
        [pscustomobject]@{ Metric = 'Host/provider assessments'; Value = $hostReport.Count }
        [pscustomobject]@{ Metric = 'Broken before script'; Value = @($hostReport | Where-Object WasBrokenBeforeScript).Count }
        [pscustomobject]@{ Metric = 'Remediation commands succeeded'; Value = @($hostReport | Where-Object CommandSucceeded).Count }
        [pscustomobject]@{ Metric = 'Fixed and verified'; Value = @($hostReport | Where-Object FixedByScript).Count }
        [pscustomobject]@{ Metric = 'Remaining noncompliant'; Value = @($hostReport | Where-Object { -not $_.FinalCompliant }).Count }
        [pscustomobject]@{ Metric = 'Key usage records'; Value = $keyUsageReport.Count }
        [pscustomobject]@{ Metric = 'Unique key/provider pairs'; Value = $allKeysReport.Count }
        [pscustomobject]@{ Metric = 'Recent key threshold (days)'; Value = $RecentKeyDays }
        [pscustomobject]@{ Metric = 'Event lookback (days)'; Value = $EventLookbackDays }
        [pscustomobject]@{ Metric = 'Event retrieval mode'; Value = $(if ($SkipEventHistory) { 'Skipped' } elseif ($DeepEventScan) { 'Deep full-range scan' } else { "Bounded newest $EventMaxSamples events" }) }
        [pscustomobject]@{ Metric = 'Run log'; Value = $LogPath }
        [pscustomobject]@{ Metric = 'Persistent key history'; Value = $KeyHistoryPath }
        [pscustomobject]@{ Metric = 'Provider-related historical events'; Value = $providerEventReport.Count }
        [pscustomobject]@{ Metric = 'Source vCenter comparison'; Value = $(if ($SourceVCenter) { $SourceVCenter } else { 'Not requested' }) }
        [pscustomobject]@{ Metric = 'Source key usage records'; Value = $sourceKeyUsageReport.Count }
        [pscustomobject]@{ Metric = 'Target vCenter key-status records'; Value = $vCenterKeyStatusReport.Count }
        [pscustomobject]@{ Metric = 'HCX readiness records'; Value = $hcxReadinessReport.Count }
        [pscustomobject]@{ Metric = 'Source provider comparisons'; Value = $sourceProviderReport.Count }
        [pscustomobject]@{ Metric = 'Cluster readiness records'; Value = $clusterReadinessReport.Count }
        [pscustomobject]@{ Metric = 'Storage policy records'; Value = $storagePolicyReport.Count }
        [pscustomobject]@{ Metric = 'Date interpretation'; Value = 'Assignment dates require assignment/rekey language; backup/status events are excluded. ObservationOnly is not an assignment date.' }
        [pscustomobject]@{ Metric = 'Errors'; Value = $errorReport.Count }
        [pscustomobject]@{ Metric = 'Compliance rule'; Value = 'Connected + PoweredOn + CryptoState=safe; provider/key observations are reported separately.' }
    )

    $sets = [ordered]@{
        'Summary' = $summary
        'Providers' = @($providersReport)
        'Host Status' = @($hostReport)
        'Key Usage' = @($keyUsageReport)
        'All Keys' = @($allKeysReport)
        'Provider Events' = @($providerEventReport)
        'Source Providers' = @($sourceProviderReport)
        'Source Key Usage' = @($sourceKeyUsageReport)
        'vCenter Key Status' = @($vCenterKeyStatusReport)
        'HCX Readiness' = @($hcxReadinessReport)
        'Cluster Readiness' = @($clusterReadinessReport)
        'Storage Policies' = @($storagePolicyReport)
        'Errors' = @($errorReport)
    }

    foreach ($name in $sets.Keys) {
        $safeName = $name -replace '[^A-Za-z0-9._-]', '_'
        @($sets[$name]) | Export-Csv -Path (Join-Path $csvDirectory ($safeName + '.csv')) -NoTypeInformation -Encoding utf8
    }

    if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Force }
    $first = $true
    foreach ($name in $sets.Keys) {
        $rows = @($sets[$name])
        if (-not $rows.Count) { $rows = @([pscustomobject]@{ Status = 'No records collected.' }) }
        $parameters = @{
            Path = $OutputPath; WorksheetName = $name; AutoSize = $true; AutoFilter = $true
            FreezeTopRow = $true; BoldTopRow = $true; TableName = (($name -replace '[^A-Za-z0-9]', '') + 'Table')
            TableStyle = $(if ($name -eq 'Errors') { 'Medium10' } else { 'Medium2' })
        }
        if (-not $first) { $parameters.Append = $true }
        $rows | Export-Excel @parameters
        $first = $false
    }
    Write-Host "Excel report: $OutputPath" -ForegroundColor Green
    Write-Host "CSV copies:  $csvDirectory" -ForegroundColor Green
}

try {
    Write-RunLog 'Checking and loading prerequisite modules.'
    $modules = @('VMware.VimAutomation.Core', 'VMware.VimAutomation.Storage', 'ImportExcel')
    foreach ($module in $modules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            if (-not $InstallPrerequisites) { throw "Required module '$module' is missing. Re-run with -InstallPrerequisites." }
            Write-Host "Installing $module for the current user..." -ForegroundColor Cyan
            Install-Module -Name $module -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
        }
        Import-Module $module -ErrorAction Stop -Verbose:$false
    }

    if ($IgnoreInvalidCertificate) {
        Set-PowerCLIConfiguration -Scope Session -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
    }
    if (-not $Credential) { $Credential = Get-Credential -Message "Credentials for $vCenter" }
    Write-RunLog "Connecting to vCenter $vCenter."
    $script:viServer = Connect-VIServer -Server $vCenter -Credential $Credential -ErrorAction Stop
    $connected = $true
    Write-RunLog 'Connected to vCenter. Retrieving Native Key Providers.'

    $script:selectedProviders = @(Get-KeyProvider -Server $script:viServer -Type NativeKeyProvider -ErrorAction Stop)
    if ($KeyProvider) { $script:selectedProviders = @($script:selectedProviders | Where-Object Name -in $KeyProvider) }
    if (-not $script:selectedProviders.Count) { throw 'No matching Native Key Providers were found.' }

    foreach ($provider in $script:selectedProviders) {
        $providersReport.Add([pscustomobject]@{
            ProviderName = [string]$provider.Name; ProviderId = Get-ProviderId $provider
            ProviderType = [string](Get-FirstValue $provider @('Type', 'KeyProviderType'))
            Status = [string](Get-FirstValue $provider @('Status', 'State', 'ConnectionStatus'))
            IsDefault = [string](Get-FirstValue $provider @('IsDefault', 'DefaultForSystem'))
            BackupState = [string](Get-FirstValue $provider @('BackupStatus', 'BackupState', 'IsBackedUp', 'BackedUp') 'Not exposed by this PowerCLI object')
            KeyId = [string](Get-FirstValue $provider @('KeyId', 'NativeKeyId'))
            CurrentStateEvidence = 'Current Get-KeyProvider object; historical events are reported separately and do not override current state.'
        })
    }

    Write-RunLog 'Retrieving clusters and host inventory.'
    $clusters = @(Get-Cluster -Server $script:viServer -ErrorAction Stop)
    if ($Cluster) { $clusters = @($clusters | Where-Object Name -in $Cluster) }
    if (-not $clusters.Count) { throw 'No matching clusters were found.' }

    $workItems = [System.Collections.Generic.List[object]]::new()
    foreach ($clusterObject in $clusters) {
        $dc = Get-Datacenter -Cluster $clusterObject -Server $script:viServer -ErrorAction SilentlyContinue | Select-Object -First 1
        foreach ($hostObject in @(Get-VMHost -Location $clusterObject -Server $script:viServer -ErrorAction Stop | Sort-Object Name)) {
            foreach ($provider in $script:selectedProviders) {
                $initial = Get-HostSnapshot -VMHost $hostObject -Provider $provider
                if ($initial.ReadError) { Add-ErrorRecord 'InitialHostInventory' 'VMHost' $hostObject.Name $initial.ReadError }
                Add-KeyUsage 'HostRuntime' $initial.RuntimeKeyId $initial.RuntimeProviderId 'ESXi coredump/runtime key' 'VMHost' $hostObject.Name $dc.Name $clusterObject.Name $hostObject.Name '' '' 'HostRuntimeInfo.cryptoKeyId'
                foreach ($cacheKey in $initial.CacheKeys) {
                    Add-KeyUsage 'HostCryptoManager' $cacheKey.KeyId $cacheKey.ProviderId 'Host key cache' 'VMHost' $hostObject.Name $dc.Name $clusterObject.Name $hostObject.Name '' '' 'CryptoManager.ListKeys'
                }
                $workItems.Add([pscustomobject]@{
                    Datacenter = [string]$dc.Name; Cluster = [string]$clusterObject.Name
                    Host = $hostObject; Provider = $provider; Initial = $initial
                    Eligible = [bool]($initial.Reachable -and -not $initial.ReadError)
                    Attempted = $false; CommandSucceeded = $false; RemediationError = ''; RemediationResult = ''
                })
            }
        }
    }

    Write-RunLog ("Host/provider assessments collected: {0}. Beginning remediation decision pass." -f $workItems.Count)
    foreach ($item in $workItems) {
        if (-not $Remediate) {
            $item.RemediationResult = if ($item.Initial.Compliant) { 'Already compliant; no action required.' } else { 'Audit only; remediation not requested.' }
            continue
        }
        if ($item.Initial.Compliant -and -not $RefreshSafeHosts) {
            $item.RemediationResult = 'Already compliant; no action required. Use -RefreshSafeHosts with -Remediate only when an explicit host-key refresh is required.'
            continue
        }
        if (-not $item.Eligible) {
            $item.RemediationResult = 'Not eligible: host must be connected, powered on, and readable through CryptoManager.'
            continue
        }
        $target = "$($item.Host.Name) / $($item.Provider.Name)"
        if ($item.Initial.Compliant -and $RefreshSafeHosts) { Write-RunLog "Explicit safe-host key refresh requested for $target." 'WARN' }
        if ($PSCmdlet.ShouldProcess($target, 'Assign NKP and configure or refresh the ESXi host encryption key')) {
            $item.Attempted = $true
            try {
                Set-VMHost -VMHost $item.Host -KeyProvider $item.Provider -Confirm:$false -ErrorAction Stop | Out-Null
                $item.CommandSucceeded = $true
                $item.RemediationResult = 'Set-VMHost completed successfully; pending verification.'
            } catch {
                $item.RemediationError = $_.Exception.Message
                $item.RemediationResult = 'Set-VMHost failed.'
                Add-ErrorRecord 'Remediation' 'VMHost' $item.Host.Name $_.Exception.Message
            }
        } else { $item.RemediationResult = 'Skipped by WhatIf or explicit confirmation response.' }
    }

    if (@($workItems | Where-Object CommandSucceeded).Count -and $PropagationSeconds -gt 0) {
        Write-Host "Waiting once for $PropagationSeconds seconds before verifying all remediated hosts..." -ForegroundColor Cyan
        Start-Sleep -Seconds $PropagationSeconds
    }

    foreach ($item in $workItems) {
        $final = $item.Initial
        $verificationPerformed = $false
        $verificationError = ''
        if ($item.Attempted) {
            $verificationPerformed = $true
            try {
                $refreshedHost = Get-VMHost -Name $item.Host.Name -Server $script:viServer -ErrorAction Stop
                $refreshedHost.ExtensionData.UpdateViewData('Runtime.CryptoState', 'Runtime.CryptoKeyId')
                $final = Get-HostSnapshot -VMHost $refreshedHost -Provider $item.Provider
                if ($final.ReadError) { throw $final.ReadError }
            } catch {
                $verificationError = $_.Exception.Message
                Add-ErrorRecord 'Verification' 'VMHost' $item.Host.Name $verificationError
            }
        }
        $fixed = [bool](-not $item.Initial.Compliant -and $item.Attempted -and $item.CommandSucceeded -and $verificationPerformed -and -not $verificationError -and $final.Compliant)
        $status = if ($item.Initial.Compliant -and $item.Attempted -and $item.CommandSucceeded -and $final.Compliant) { 'SafeHostRefreshed' }
            elseif ($item.Initial.Compliant) { 'AlreadyHealthy' }
            elseif (-not $Remediate) { 'BrokenBeforeScript' }
            elseif (-not $item.Eligible) { 'NotEligible' }
            elseif (-not $item.Attempted) { 'NotAttempted' }
            elseif (-not $item.CommandSucceeded) { 'CommandFailed' }
            elseif ($verificationError) { 'CouldNotVerify' }
            elseif ($fixed) { 'FixedByScript' }
            else { 'StillBroken' }
        if ($fixed) { $item.RemediationResult = 'Fixed and verified: Set-VMHost succeeded and the host reached CryptoState=safe.' }

        $hostReport.Add([pscustomobject]@{
            vCenter = $vCenter; Datacenter = $item.Datacenter; Cluster = $item.Cluster; Host = $item.Host.Name; HostVersion = $item.Host.Version
            ProviderName = $item.Provider.Name; ProviderId = Get-ProviderId $item.Provider
            ConnectionState = $item.Host.ConnectionState; PowerState = $item.Host.PowerState
            InitialCryptoState = $item.Initial.CryptoState; FinalCryptoState = $final.CryptoState
            InitialRuntimeKeyId = $item.Initial.RuntimeKeyId; FinalRuntimeKeyId = $final.RuntimeKeyId
            InitialRuntimeProviderId = $item.Initial.RuntimeProviderId; FinalRuntimeProviderId = $final.RuntimeProviderId
            InitialProviderObserved = $item.Initial.ProviderObserved; FinalProviderObserved = $final.ProviderObserved
            InitialHostCacheKeyCount = $item.Initial.HostCacheKeyCount; FinalHostCacheKeyCount = $final.HostCacheKeyCount
            InitialCompliant = $item.Initial.Compliant; FinalCompliant = $final.Compliant
            WasBrokenBeforeScript = -not $item.Initial.Compliant; RemediationEligible = $item.Eligible
            RemediationAttempted = $item.Attempted; CommandSucceeded = $item.CommandSucceeded
            VerificationPerformed = $verificationPerformed; FixedByScript = $fixed; FixStatus = $status
            RemediationResult = $item.RemediationResult; InitialError = $item.Initial.ReadError
            RemediationError = $item.RemediationError; VerificationError = $verificationError
        })
    }

    # VM home and virtual-disk keys identify which provider/key protects each VM object.
    Write-RunLog 'Collecting VM home and virtual-disk key assignments.'
    foreach ($vmView in @(Get-View -ViewType VirtualMachine -Server $script:viServer -Property Name,Config.KeyId,Config.Hardware.Device,Runtime.Host,Parent -ErrorAction Stop)) {
        try {
            $vmObject = Get-VIObjectByVIView -VIView $vmView
            $vmHost = if ($vmView.Runtime.Host) { Get-VMHost -Id $vmView.Runtime.Host -Server $script:viServer -ErrorAction SilentlyContinue } else { $null }
            $clusterName = if ($vmHost) { [string](Get-Cluster -VMHost $vmHost -Server $script:viServer -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Name) } else { '' }
            $isTemplate = $vmObject.GetType().FullName -match 'Template'
            $dcName = if (-not $isTemplate) { [string](Get-Datacenter -VM $vmObject -Server $script:viServer -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Name) } else { '' }
            $vmKey = ConvertTo-KeyIdentity $vmView.Config.KeyId
            Add-KeyUsage 'VMConfig' $vmKey.KeyId $vmKey.ProviderId 'VM home/config encryption key' 'VirtualMachine' $vmView.Name $dcName $clusterName $(if ($vmHost) { $vmHost.Name } else { '' }) $vmView.Name '' 'VirtualMachineConfigInfo.keyId'
            foreach ($device in @($vmView.Config.Hardware.Device | Where-Object { $_ -is [VMware.Vim.VirtualDisk] })) {
                $diskKey = ConvertTo-KeyIdentity $device.Backing.KeyId
                $label = [string]$device.DeviceInfo.Label
                $details = [string](Get-FirstValue $device.Backing @('FileName', 'DeviceName'))
                Add-KeyUsage 'VMDisk' $diskKey.KeyId $diskKey.ProviderId 'Virtual disk encryption key' 'VirtualDisk' "$($vmView.Name)/$label" $dcName $clusterName $(if ($vmHost) { $vmHost.Name } else { '' }) $vmView.Name $label $details
            }
        } catch { Add-ErrorRecord 'VMKeyInventory' 'VirtualMachine' $vmView.Name $_.Exception.Message }
    }

    Write-RunLog ("VM and host key usage records collected so far: {0}." -f $keyUsageReport.Count)

    # vCenter ListKeys inventory. It returns identifiers, not plaintext key material.
    try {
        $service = Get-View -Id ServiceInstance -Server $script:viServer -ErrorAction Stop
        $vcCrypto = Get-View -Id $service.Content.CryptoManager -Server $script:viServer -ErrorAction Stop
        foreach ($key in @($vcCrypto.ListKeys(0))) {
            $identity = ConvertTo-KeyIdentity $key
            Add-KeyUsage 'vCenterCryptoManager' $identity.KeyId $identity.ProviderId 'Key known to vCenter' 'vCenter' $vCenter '' '' '' '' '' 'CryptoManager.ListKeys'
        }
    } catch { Add-ErrorRecord 'vCenterKeyInventory' 'vCenter' $vCenter $_.Exception.Message }

    # Destination cluster defaults and encryption storage-policy evidence.
    foreach ($clusterObject in $clusters) {
        $defaultProviderName = ''; $defaultProviderId = ''; $defaultProviderError = ''
        try {
            if (Get-Command Get-EntityDefaultKeyProvider -ErrorAction SilentlyContinue) {
                $clusterDefault = Get-EntityDefaultKeyProvider -Entity $clusterObject -Server $script:viServer -ErrorAction Stop
                if ($clusterDefault) { $defaultProviderName = [string]$clusterDefault.Name; $defaultProviderId = Get-ProviderId $clusterDefault }
            } else { $defaultProviderError = 'Get-EntityDefaultKeyProvider is not available in the installed PowerCLI version.' }
        } catch { $defaultProviderError = $_.Exception.Message }
        $clusterHosts = @(Get-VMHost -Location $clusterObject -Server $script:viServer -ErrorAction SilentlyContinue)
        $safeHosts = @($clusterHosts | Where-Object { $_.ConnectionState -eq 'Connected' -and $_.PowerState -eq 'PoweredOn' -and [string]$_.ExtensionData.Runtime.CryptoState -eq 'safe' })
        $clusterReadinessReport.Add([pscustomobject]@{
            Cluster=$clusterObject.Name; HostCount=$clusterHosts.Count; CryptoSafeHostCount=$safeHosts.Count; AllHostsCryptoSafe=[bool]($clusterHosts.Count -and $clusterHosts.Count -eq $safeHosts.Count)
            ClusterDefaultProviderName=$defaultProviderName; ClusterDefaultProviderId=$defaultProviderId
            SelectedProvider=(@($script:selectedProviders.Name) -join '; '); DefaultProviderMatchesSelected=[bool]($defaultProviderName -and @($script:selectedProviders.Name) -contains $defaultProviderName)
            DefaultProviderQueryError=$defaultProviderError
        })
    }
    try {
        $policies = @(Get-SpbmStoragePolicy -Server $script:viServer -ErrorAction Stop)
        foreach ($policy in $policies) {
            $policyText = "$($policy.Name) $($policy.Description)"
            $looksEncrypted = $policyText -match '(?i)encrypt|cryptographic'
            if ($EncryptionStoragePolicyName -or $looksEncrypted) {
                $storagePolicyReport.Add([pscustomobject]@{
                    PolicyName=$policy.Name; Description=$policy.Description; IsRequestedPolicy=[bool]($EncryptionStoragePolicyName -and $policy.Name -ieq $EncryptionStoragePolicyName)
                    EncryptionCandidate=$looksEncrypted; PolicyCategory=[string]$policy.PolicyCategory; CreationTime=[string]$policy.CreationTime; LastUpdatedTime=[string]$policy.LastUpdatedTime
                    HCXUse='Select an encryption-capable destination storage policy in the HCX migration UI.'
                })
            }
        }
        if ($EncryptionStoragePolicyName -and -not @($storagePolicyReport | Where-Object IsRequestedPolicy).Count) { Add-ErrorRecord 'StoragePolicy' 'SPBMPolicy' $EncryptionStoragePolicyName 'Requested encryption storage policy was not found on the destination vCenter.' }
    } catch { Add-ErrorRecord 'StoragePolicyInventory' 'vCenter' $vCenter $_.Exception.Message }

    # Optional read-only source-vCenter inventory for HCX and cross-vCenter comparison.
    if ($SourceVCenter) {
        try {
            if (-not $SourceCredential) { $SourceCredential = Get-Credential -Message "Credentials for source vCenter $SourceVCenter" }
            Write-RunLog "Connecting read-only to source vCenter $SourceVCenter for key comparison."
            $script:sourceViServer = Connect-VIServer -Server $SourceVCenter -Credential $SourceCredential -ErrorAction Stop
            $sourceConnected = $true
            $sourceProviders = @(Get-KeyProvider -Server $script:sourceViServer -Type NativeKeyProvider -ErrorAction Stop)
            foreach ($sourceProvider in $sourceProviders) {
                $sourceProviderId = Get-ProviderId $sourceProvider
                $sourceNativeKeyId = [string](Get-FirstValue $sourceProvider @('KeyId','NativeKeyId'))
                $targetMatch = $script:selectedProviders | Where-Object { $_.Name -ieq $sourceProvider.Name } | Select-Object -First 1
                $targetNativeKeyId = if ($targetMatch) { [string](Get-FirstValue $targetMatch @('KeyId','NativeKeyId')) } else { '' }
                $sourceProviderReport.Add([pscustomobject]@{
                    SourceVCenter=$SourceVCenter; SourceProviderName=$sourceProvider.Name; SourceProviderId=$sourceProviderId; SourceNativeKeyId=$sourceNativeKeyId
                    TargetVCenter=$vCenter; TargetProviderFound=[bool]$targetMatch; TargetProviderName=if($targetMatch){$targetMatch.Name}else{''}; TargetProviderId=if($targetMatch){Get-ProviderId $targetMatch}else{''}; TargetNativeKeyId=$targetNativeKeyId
                    NameMatch=[bool]($targetMatch -and $targetMatch.Name -ieq $sourceProvider.Name)
                    NativeKeyIdMatch=[bool]($sourceNativeKeyId -and $targetNativeKeyId -and $sourceNativeKeyId -eq $targetNativeKeyId)
                    ComparisonResult=if(-not $targetMatch){'BLOCKED: provider name not found on target'}elseif($sourceNativeKeyId -and $targetNativeKeyId -and $sourceNativeKeyId -ne $targetNativeKeyId){'BLOCKED: provider name matches but native key identity differs'}else{'Provider identity appears compatible; verify source key availability results'}
                })
            }
            $sourceVmViews = @(Get-View -ViewType VirtualMachine -Server $script:sourceViServer -Property Name,Config.KeyId,Config.Hardware.Device -ErrorAction Stop)
            if ($HCXVMName) { $sourceVmViews = @($sourceVmViews | Where-Object { $_.Name -in $HCXVMName }) }
            foreach ($sourceVm in $sourceVmViews) {
                $sourceVmKey = ConvertTo-KeyIdentity $sourceVm.Config.KeyId
                if ($sourceVmKey.KeyId -or $sourceVmKey.ProviderId) {
                    $sourceKeyUsageReport.Add([pscustomobject]@{ SourceVCenter=$SourceVCenter; ObjectType='VirtualMachine'; ObjectName=$sourceVm.Name; Device='VM home/config'; KeyId=$sourceVmKey.KeyId; ProviderId=$sourceVmKey.ProviderId })
                }
                foreach ($sourceDisk in @($sourceVm.Config.Hardware.Device | Where-Object { $_ -is [VMware.Vim.VirtualDisk] })) {
                    $sourceDiskKey = ConvertTo-KeyIdentity $sourceDisk.Backing.KeyId
                    if ($sourceDiskKey.KeyId -or $sourceDiskKey.ProviderId) {
                        $sourceKeyUsageReport.Add([pscustomobject]@{ SourceVCenter=$SourceVCenter; ObjectType='VirtualDisk'; ObjectName=$sourceVm.Name; Device=[string]$sourceDisk.DeviceInfo.Label; KeyId=$sourceDiskKey.KeyId; ProviderId=$sourceDiskKey.ProviderId })
                    }
                }
            }
            Write-RunLog ("Source key inventory complete. Records={0}." -f $sourceKeyUsageReport.Count)
        } catch {
            Add-ErrorRecord 'SourceVCenterKeyInventory' 'vCenter' $SourceVCenter $_.Exception.Message
            Write-RunLog ("Source vCenter key inventory failed: {0}" -f $_.Exception.Message) 'ERROR'
        }
    }

    # Query destination vCenter availability and usage for all target and optional source keys.
    try {
        $queryKeys = @()
        foreach ($record in @($keyUsageReport) + @($sourceKeyUsageReport)) {
            if ([string]::IsNullOrWhiteSpace([string]$record.KeyId)) { continue }
            $queryKey = New-Object VMware.Vim.CryptoKeyId
            $queryKey.KeyId = [string]$record.KeyId
            if (-not [string]::IsNullOrWhiteSpace([string]$record.ProviderId)) {
                $queryProvider = New-Object VMware.Vim.KeyProviderId
                $queryProvider.Id = [string]$record.ProviderId
                $queryKey.ProviderId = $queryProvider
            }
            $queryKeys += $queryKey
        }
        $queryKeys = @($queryKeys | Group-Object { "$($_.ProviderId.Id)|$($_.KeyId)" } | ForEach-Object { $_.Group[0] })
        if ($queryKeys.Count) {
            Write-RunLog ("Querying target vCenter key status for {0} unique keys." -f $queryKeys.Count)
            foreach ($keyStatus in @($vcCrypto.QueryCryptoKeyStatus($queryKeys, 15))) {
                $statusIdentity = ConvertTo-KeyIdentity $keyStatus.KeyId
                $vmNames = @(); foreach ($vmRef in @($keyStatus.EncryptedVMs)) { try { $vmNames += (Get-View -Id $vmRef -Server $script:viServer -Property Name).Name } catch { $vmNames += [string]$vmRef } }
                $hostNames = @(); foreach ($hostRef in @($keyStatus.AffectedHosts)) { try { $hostNames += (Get-View -Id $hostRef -Server $script:viServer -Property Name).Name } catch { $hostNames += [string]$hostRef } }
                $fromSource = [bool](@($sourceKeyUsageReport | Where-Object { $_.KeyId -eq $statusIdentity.KeyId -and $_.ProviderId -eq $statusIdentity.ProviderId }).Count)
                $available = Get-FirstValue $keyStatus @('KeyAvailable','Available')
                $vCenterKeyStatusReport.Add([pscustomobject]@{
                    TargetVCenter=$vCenter; ProviderId=$statusIdentity.ProviderId; KeyId=$statusIdentity.KeyId
                    KeyAvailableToTargetVCenter=[string]$available; Reason=[string](Get-FirstValue $keyStatus @('Reason','Status'))
                    EncryptedVMs=(@($vmNames | Sort-Object -Unique) -join '; '); AffectedHosts=(@($hostNames | Sort-Object -Unique) -join '; ')
                    ThirdPartyReferences=(@((Get-FirstValue $keyStatus @('ReferencedByTags','ReferencedBy'))) -join '; ')
                    DiscoveredOnSourceVCenter=$fromSource
                    DestinationReadiness=$(if ($available -eq $true) { 'Available' } elseif ($fromSource) { 'BLOCKED: source key not available on target vCenter' } else { 'Not available or status unknown' })
                })
            }
        }
    } catch {
        Add-ErrorRecord 'TargetVCenterKeyStatus' 'vCenter' $vCenter $_.Exception.Message
        Write-RunLog ("Target vCenter QueryCryptoKeyStatus failed: {0}" -f $_.Exception.Message) 'ERROR'
    }

    # Optional HCX readiness evidence. No ESXi management service is restarted automatically.
    if ($IncludeHCXReadiness) {
        Write-RunLog 'Collecting HCX encrypted-migration readiness evidence.'
        foreach ($clusterObject in $clusters) {
            foreach ($hcxHost in @(Get-VMHost -Location $clusterObject -Server $script:viServer -ErrorAction SilentlyContinue)) {
                $runtimeProvider = [string](ConvertTo-KeyIdentity $hcxHost.ExtensionData.Runtime.CryptoKeyId).ProviderId
                $hbrServices = @(Get-VMHostService -VMHost $hcxHost -Server $script:viServer -ErrorAction SilentlyContinue | Where-Object { $_.Key -match '(?i)hbr' -or $_.Label -match '(?i)replication|hbr' })
                $hbrFirewall = @(Get-VMHostFirewallException -VMHost $hcxHost -Server $script:viServer -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)hbr|replication' })
                $hbrVibs = @(); try { $esxcli = Get-EsxCli -VMHost $hcxHost -V2 -Server $script:viServer -ErrorAction Stop; $hbrVibs = @($esxcli.software.vib.list.Invoke() | Where-Object { $_.Name -match '(?i)hbr' }) } catch { }
                $triggeredAlarms = @(); try { $triggeredAlarms = @($hcxHost.ExtensionData.TriggeredAlarmState | ForEach-Object { (Get-View -Id $_.Alarm -Server $script:viServer -Property Info.Name).Info.Name }) } catch { }
                $providerMatch = [bool](@($script:selectedProviders | Where-Object { (Get-ProviderId $_) -ieq $runtimeProvider }).Count)
                $hcxReadinessReport.Add([pscustomobject]@{
                    Cluster=$clusterObject.Name; Host=$hcxHost.Name; ConnectionState=$hcxHost.ConnectionState; PowerState=$hcxHost.PowerState
                    CryptoState=[string]$hcxHost.ExtensionData.Runtime.CryptoState; RuntimeProviderId=$runtimeProvider; SelectedProvider=(@($script:selectedProviders.Name) -join '; '); ProviderMatch=$providerMatch
                    HBRServiceFound=[bool]$hbrServices.Count; HBRServiceRunning=[bool](@($hbrServices | Where-Object Running).Count); HBRServiceDetails=(@($hbrServices | ForEach-Object { "$($_.Key):Running=$($_.Running)" }) -join '; ')
                    HBRFirewallRuleFound=[bool]$hbrFirewall.Count; HBRFirewallEnabled=[bool](@($hbrFirewall | Where-Object Enabled).Count)
                    HBRVibFound=[bool]$hbrVibs.Count; HBRVibDetails=(@($hbrVibs | ForEach-Object { "$($_.Name):$($_.Version)" }) -join '; '); TriggeredAlarms=(@($triggeredAlarms | Sort-Object -Unique) -join '; ')
                    Port32032Requirement='Validate secure listener and end-to-end TCP 32032 outside this report.'
                    Readiness=$(if ($hcxHost.ConnectionState -ne 'Connected' -or $hcxHost.PowerState -ne 'PoweredOn') { 'Not ready: host unavailable' } elseif ([string]$hcxHost.ExtensionData.Runtime.CryptoState -ne 'safe') { 'Not ready: host is not crypto safe' } elseif (-not $providerMatch) { 'Review: runtime provider does not match selected NKP' } elseif (-not $hbrVibs.Count) { 'Review: HBR VIB not detected' } elseif ($hbrServices.Count -and -not (@($hbrServices | Where-Object Running).Count)) { 'Not ready: HBR service found but not running' } else { 'Crypto ready; validate HCX HBR agent, encryption storage policy, service mesh, and TCP 32032' })
                })
            }
        }
    }

    # Best-effort assignment evidence. CryptoKeyId does not expose an assignment timestamp, so the
    # report combines retained vCenter events with a persistent first-seen ledger. Dates are labeled
    # by source and are never presented as authoritative when only observation history is available.
    $cryptoEvents = @()
    if ($SkipEventHistory) {
        Write-RunLog 'Skipping vCenter event history by request. Assignment dates will use persistent first-seen history.' 'WARN'
    } else {
        try {
            $eventStart = (Get-Date).AddDays(-$EventLookbackDays)
            if ($DeepEventScan) {
                Write-RunLog ("Deep event scan started for {0} days. This can take a long time on a busy vCenter." -f $EventLookbackDays) 'WARN'
                $candidateEvents = @(Get-VIEvent -Server $script:viServer -Start $eventStart -Finish (Get-Date) -ErrorAction Stop)
            } else {
                Write-RunLog ("Bounded event scan started: newest {0} events, then filtered to the last {1} days. Use -DeepEventScan only when full retained coverage is required." -f $EventMaxSamples, $EventLookbackDays)
                $candidateEvents = @(Get-VIEvent -Server $script:viServer -MaxSamples $EventMaxSamples -ErrorAction Stop | Where-Object { $_.CreatedTime -ge $eventStart })
            }
            $cryptoEvents = @($candidateEvents | Where-Object {
                $_.FullFormattedMessage -match '(?i)crypt|encrypt|rekey|key provider|keyprovider|KMS|NKP'
            })
            Write-RunLog ("Event scan complete. Candidate events={0}; crypto-related events={1}." -f $candidateEvents.Count, $cryptoEvents.Count)
        } catch {
            Add-ErrorRecord 'CryptoEventInventory' 'vCenter' $vCenter $_.Exception.Message
            Write-RunLog ("Event scan failed: {0}" -f $_.Exception.Message) 'ERROR'
        }
    }

    foreach ($provider in $script:selectedProviders) {
        $providerIdForEvent = Get-ProviderId $provider
        foreach ($event in @($cryptoEvents | Where-Object { $_.FullFormattedMessage -match [regex]::Escape($providerIdForEvent) } | Sort-Object CreatedTime)) {
            $message = [string]$event.FullFormattedMessage
            $category = if ($message -match '(?i)not backed up|backup|back-up') { 'Backup history' } elseif ($message -match '(?i)assign|rekey|recrypt|encrypt|configured? crypto|change(?:d)? key') { 'Crypto operation' } else { 'Provider-related event' }
            $disposition = if ($category -eq 'Backup history') { 'Historical observation only; does not override current provider state.' } else { 'Review for operational context.' }
            $providerEventReport.Add([pscustomobject]@{
                CreatedTimeUtc = ([datetime]$event.CreatedTime).ToUniversalTime().ToString('o')
                ProviderName = $provider.Name; ProviderId = $providerIdForEvent
                Category = $category; EventType = $event.GetType().Name; UserName = [string]$event.UserName
                Message = $message; Disposition = $disposition
            })
        }
    }

    $history = @{}
    if (Test-Path -LiteralPath $KeyHistoryPath) {
        try {
            $loadedHistory = Get-Content -LiteralPath $KeyHistoryPath -Raw | ConvertFrom-Json
            foreach ($entry in @($loadedHistory)) { $history[[string]$entry.Identity] = $entry }
        } catch { Add-ErrorRecord 'KeyHistoryRead' 'HistoryFile' $KeyHistoryPath $_.Exception.Message }
    }
    $historyOutput = [System.Collections.Generic.List[object]]::new()

    # Reconcile unique provider/key pairs with every discovered use.
    $groups = @($keyUsageReport | Group-Object { '{0}|{1}' -f $_.ProviderId, $_.KeyId })
    foreach ($group in $groups) {
        $first = $group.Group | Select-Object -First 1
        $uses = @($group.Group | Where-Object { $_.Source -ne 'vCenterCryptoManager' })
        $identity = '{0}|{1}' -f $first.ProviderId, $first.KeyId
        $objectNames = @($uses.ObjectName | Where-Object { $_ } | Sort-Object -Unique)
        $objectSummary = (@($uses | ForEach-Object { if ($_.ObjectName) { "$($_.ObjectType):$($_.ObjectName)" } } | Sort-Object -Unique) -join '; ')
        $previous = $history[$identity]
        $firstSeenUtc = if ($previous -and $previous.FirstSeenUtc) { [datetime]$previous.FirstSeenUtc } else { $runStartedUtc }
        $lastSeenUtc = $runStartedUtc

        $assignmentVerbPattern = '(?i)assign|configured? crypto|change(?:d)? key|rekey|recrypt|encrypt(?:ed|ion)?|enable(?:d)? crypto|set (?:the )?key'
        $excludedEventPattern = '(?i)not backed up|backup|back-up|alarm|warning|health|status|certificate|connection'
        $exactEvents = @($cryptoEvents | Where-Object {
            $message = [string]$_.FullFormattedMessage
            $message -and $message.Contains([string]$first.KeyId) -and
            $message -match $assignmentVerbPattern -and $message -notmatch $excludedEventPattern
        } | Sort-Object CreatedTime)
        $inferredEvents = @()
        if (-not $exactEvents.Count -and $objectNames.Count) {
            $inferredEvents = @($cryptoEvents | Where-Object {
                $message = [string]$_.FullFormattedMessage
                $message -match $assignmentVerbPattern -and $message -notmatch $excludedEventPattern -and
                (@($objectNames | Where-Object { $message -match [regex]::Escape([string]$_) }).Count -gt 0)
            } | Sort-Object CreatedTime)
        }
        $assignmentEvent = if ($exactEvents.Count) { $exactEvents | Select-Object -First 1 } elseif ($inferredEvents.Count) { $inferredEvents | Select-Object -First 1 } else { $null }
        $dateSource = if ($exactEvents.Count) { 'vCenter assignment/rekey event containing exact KeyId' } elseif ($inferredEvents.Count) { 'vCenter assignment/rekey event inferred from exact object name' } elseif ($previous) { 'First seen by this script history; actual assignment date unavailable' } else { 'First observed by this script; actual assignment date unavailable' }
        $dateConfidence = if ($exactEvents.Count) { 'High' } elseif ($inferredEvents.Count) { 'Medium' } else { 'ObservationOnly' }
        $assignedOrObservedUtc = if ($assignmentEvent) { ([datetime]$assignmentEvent.CreatedTime).ToUniversalTime() } else { $firstSeenUtc.ToUniversalTime() }
        $ageDays = [math]::Floor(($runStartedUtc - $assignedOrObservedUtc).TotalDays)
        $recent = $ageDays -le $RecentKeyDays
        $hostList = @($uses.Host | Where-Object { $_ } | Sort-Object -Unique)
        $vmList = @($uses.VM | Where-Object { $_ } | Sort-Object -Unique)
        $diskUses = @($uses | Where-Object UsageType -eq 'Virtual disk encryption key')

        $allKeysReport.Add([pscustomobject]@{
            ProviderName = $first.ProviderName; ProviderId = $first.ProviderId; KeyId = $first.KeyId
            AssignedOrFirstObservedUtc = $assignedOrObservedUtc.ToString('o'); AssignmentDateSource = $dateSource; AssignmentDateConfidence = $dateConfidence
            FirstSeenByScriptUtc = $firstSeenUtc.ToUniversalTime().ToString('o'); LastSeenByScriptUtc = $lastSeenUtc.ToString('o')
            AgeDays = $ageDays; RecentWithinDays = $RecentKeyDays; IsRecent = $recent
            EventLookbackDays = $EventLookbackDays; MatchingEventCount = @($exactEvents).Count + @($inferredEvents).Count
            AssignmentEventType = if ($assignmentEvent) { $assignmentEvent.GetType().Name } else { '' }
            AssignmentEventUser = if ($assignmentEvent) { [string]$assignmentEvent.UserName } else { '' }
            AssignmentEventMessage = if ($assignmentEvent) { [string]$assignmentEvent.FullFormattedMessage } else { '' }
            KnownToVCenter = [bool](@($group.Group | Where-Object Source -eq 'vCenterCryptoManager').Count)
            UsageCount = $uses.Count; DistinctObjectCount = $objectNames.Count; HostCount = $hostList.Count
            VMCount = $vmList.Count; VirtualDiskCount = $diskUses.Count
            UsageTypes = (@($uses.UsageType | Sort-Object -Unique) -join '; '); Sources = (@($group.Group.Source | Sort-Object -Unique) -join '; ')
            Objects = $objectSummary; Hosts = ($hostList -join '; '); VMs = ($vmList -join '; ')
            AssignmentStatus = if ($uses.Count) { 'Mapped to inventory object(s)' } else { 'Known to vCenter; no matching host/VM/disk use found' }
            TroubleshootingFlag = if (-not $uses.Count) { 'Review: orphan/unmapped candidate' } elseif (-not $first.ProviderId) { 'Review: ProviderId missing' } else { 'None' }
            ListKeysObservation = if (@($group.Group | Where-Object Source -eq 'vCenterCryptoManager').Count) { 'Returned by vCenter ListKeys' } else { 'Not returned by vCenter ListKeys; inventory mapping remains authoritative for this report' }
        })
        $historyOutput.Add([pscustomobject]@{
            Identity = $identity; ProviderId = $first.ProviderId; KeyId = $first.KeyId
            FirstSeenUtc = $firstSeenUtc.ToUniversalTime().ToString('o'); LastSeenUtc = $lastSeenUtc.ToString('o')
            LastKnownObjects = $objectSummary; LastKnownHosts = ($hostList -join '; '); LastKnownVMs = ($vmList -join '; ')
        })
    }

    try {
        $historyOutput | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $KeyHistoryPath -Encoding utf8
    } catch { Add-ErrorRecord 'KeyHistoryWrite' 'HistoryFile' $KeyHistoryPath $_.Exception.Message }

    Write-RunLog ("Classified {0} provider-related historical events; backup/status events will not be used as key assignment dates." -f $providerEventReport.Count)
    Write-RunLog 'Writing persistent key history and Excel/CSV reports.'
    Export-WorkbookAndCsv
    $remaining = @($hostReport | Where-Object { -not $_.FinalCompliant }).Count
    Write-RunLog 'Report generation completed.'
    Write-Host "Broken before: $(@($hostReport | Where-Object WasBrokenBeforeScript).Count); fixed and verified: $(@($hostReport | Where-Object FixedByScript).Count); remaining: $remaining" -ForegroundColor $(if ($remaining) { 'Yellow' } else { 'Green' })
}
finally {
    if ($sourceConnected) { Disconnect-VIServer -Server $script:sourceViServer -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
    if ($connected -and -not $KeepConnected) { Disconnect-VIServer -Server $script:viServer -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
}
