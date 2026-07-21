#requires -RunAsAdministrator

<#
.SYNOPSIS
    Validates gateway connectivity to a Fabric workspace-level Private Link.

.DESCRIPTION
    Supports two gateway types (use -GatewayType to select, or leave as Auto):
      SHIR  - ADF Self-Hosted Integration Runtime
      OPDG  - Fabric On-premises Data Gateway

    Tests DNS, routing, TCP, TLS/SNI and HTTP for all Fabric workspace
    Private Link endpoints. It then monitors the gateway processes while
    a pipeline or query runs to prove the private endpoint is used.

    Run this script directly on every gateway node.
#>

param(
    [int]$MonitorSeconds = 120,

    [ValidateSet("Auto", "SHIR", "OPDG")]
    [string]$GatewayType = "Auto"
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Gateway type detection and configuration
# ---------------------------------------------------------------------------

if ($GatewayType -eq "Auto") {
    $shirPath   = "C:\Program Files\Microsoft Integration Runtime"
    $onPremPath = "C:\Program Files\On-premises data gateway"

    if (Test-Path $shirPath) {
        $GatewayType = "SHIR"
    }
    elseif (Test-Path $onPremPath) {
        $GatewayType = "OPDG"
    }
    else {
        Write-Warning "Could not auto-detect a gateway installation. Defaulting to SHIR."
        $GatewayType = "SHIR"
    }

    Write-Host "Auto-detected gateway type: $GatewayType" -ForegroundColor DarkCyan
}

$GatewayConfig = switch ($GatewayType) {
    "SHIR" {
        @{
            DisplayName        = "ADF Self-Hosted Integration Runtime (SHIR)"
            ServicePattern     = "DIAHost|Integration Runtime"
            ExecutablePath     = "C:\Program Files\Microsoft Integration Runtime\5.0\Shared\diahost.exe"
            RequiredMinVersion = "5.58.9377.1"
            ProcessNames       = @("diahost", "diawp")
        }
    }
    "OPDG" {
        @{
            DisplayName        = "Fabric On-premises Data Gateway"
            ServicePattern     = "PBIEgwService|On-premises data gateway"
            ExecutablePath     = "C:\Program Files\On-premises data gateway\Microsoft.PowerBI.DataMovement.GatewayCore.exe"
            RequiredMinVersion = "N/A (check gateway app)"
            ProcessNames       = @("Microsoft.PowerBI.DataMovement.GatewayCore")
        }
    }
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

$WorkspaceId = "39ad8ab6-c9cd-4e89-bdc6-8625d64b1a16"
$WorkspaceIdNoDashes = $WorkspaceId.Replace("-", "")
$ZoneCode = $WorkspaceId.Substring(0, 2)
$WorkspacePrefix = "$WorkspaceIdNoDashes.z$ZoneCode"

$FabricEndpoints = [ordered]@{
    "WorkspaceAPI" = @{
        Hostname   = "$WorkspacePrefix.w.api.fabric.microsoft.com"
        ExpectedIP = "10.151.0.144"
    }
    "Control" = @{
        Hostname   = "$WorkspacePrefix.c.fabric.microsoft.com"
        ExpectedIP = "10.151.0.145"
    }
    "OneLake" = @{
        Hostname   = "$WorkspacePrefix.onelake.fabric.microsoft.com"
        ExpectedIP = "10.151.0.146"
    }
    "DFS" = @{
        Hostname   = "$WorkspacePrefix.dfs.fabric.microsoft.com"
        ExpectedIP = "10.151.0.147"
    }
    "Blob" = @{
        Hostname   = "$WorkspacePrefix.blob.fabric.microsoft.com"
        ExpectedIP = "10.151.0.148"
    }
}

$FabricPrivateIPs = @(
    $FabricEndpoints.Values |
        ForEach-Object { $_.ExpectedIP }
)

$GlobalEndpoints = @(
    "onelake.dfs.fabric.microsoft.com",
    "onelake.blob.fabric.microsoft.com",
    "api.fabric.microsoft.com"
)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

function Test-IsPrivateIPv4 {
    param([string]$IPAddress)

    if ($IPAddress -match "^10\.") {
        return $true
    }

    if ($IPAddress -match "^192\.168\.") {
        return $true
    }

    if ($IPAddress -match "^172\.(1[6-9]|2[0-9]|3[0-1])\.") {
        return $true
    }

    return $false
}

function Resolve-IPv4Address {
    param([string]$Hostname)

    try {
        return @(
            Resolve-DnsName $Hostname -Type A -ErrorAction Stop |
                Where-Object IPAddress |
                Select-Object -ExpandProperty IPAddress -Unique
        )
    }
    catch {
        return @()
    }
}

function Test-TcpPort {
    param(
        [string]$IPAddress,
        [int]$Port = 443,
        [int]$TimeoutMilliseconds = 10000
    )

    $client = [System.Net.Sockets.TcpClient]::new()

    try {
        $task = $client.ConnectAsync($IPAddress, $Port)

        if (-not $task.Wait($TimeoutMilliseconds)) {
            throw "TCP connection timed out after $TimeoutMilliseconds ms."
        }

        $task.GetAwaiter().GetResult()
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Test-TlsAndHttp {
    param(
        [string]$Hostname,
        [string]$IPAddress,
        [int]$TimeoutMilliseconds = 15000
    )

    $result = [ordered]@{
        TLS       = $false
        HTTP      = $false
        HTTPStatus = $null
        CertificateSubject = $null
        CertificateIssuer  = $null
        Error     = $null
    }

    $tcpClient = [System.Net.Sockets.TcpClient]::new()

    try {
        $tcpClient.ReceiveTimeout = $TimeoutMilliseconds
        $tcpClient.SendTimeout = $TimeoutMilliseconds

        # Connect directly to the expected private IP.
        $connectTask = $tcpClient.ConnectAsync($IPAddress, 443)

        if (-not $connectTask.Wait($TimeoutMilliseconds)) {
            throw "TCP connection timed out."
        }

        $connectTask.GetAwaiter().GetResult()

        # Authenticate using the hostname. This sends the hostname as TLS SNI.
        $sslStream = [System.Net.Security.SslStream]::new(
            $tcpClient.GetStream(),
            $false
        )

        $tlsTask = $sslStream.AuthenticateAsClientAsync($Hostname)

        if (-not $tlsTask.Wait($TimeoutMilliseconds)) {
            throw "TLS handshake timed out."
        }

        $tlsTask.GetAwaiter().GetResult()
        $result.TLS = $true

        if ($sslStream.RemoteCertificate) {
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $sslStream.RemoteCertificate
            )

            $result.CertificateSubject = $certificate.Subject
            $result.CertificateIssuer = $certificate.Issuer
        }

        # Send an unauthenticated HEAD request. HTTP 400/401/403 is acceptable:
        # it proves DNS, TCP and TLS are working end-to-end.
        $request = @(
            "HEAD / HTTP/1.1"
            "Host: $Hostname"
            "User-Agent: Fabric-PrivateLink-Test"
            "Connection: close"
            ""
            ""
        ) -join "`r`n"

        $requestBytes = [System.Text.Encoding]::ASCII.GetBytes($request)
        $sslStream.Write($requestBytes, 0, $requestBytes.Length)
        $sslStream.Flush()

        $reader = [System.IO.StreamReader]::new($sslStream)
        $statusLine = $reader.ReadLine()

        if ($statusLine) {
            $result.HTTP = $true
            $result.HTTPStatus = $statusLine
        }

        $reader.Dispose()
        $sslStream.Dispose()
    }
    catch {
        $message = $_.Exception.Message

        if ($_.Exception.InnerException) {
            $message += " | Inner: $($_.Exception.InnerException.Message)"
        }

        $result.Error = $message
    }
    finally {
        $tcpClient.Dispose()
    }

    return [PSCustomObject]$result
}

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Fabric Workspace Private Link — $GatewayType Validation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Workspace: $WorkspaceId"
Write-Host "Computer:  $env:COMPUTERNAME"
Write-Host "Time:      $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Local network configuration
# ---------------------------------------------------------------------------

Write-Host "1. Gateway VM network configuration" -ForegroundColor Yellow

Get-NetIPConfiguration |
    Where-Object IPv4Address |
    ForEach-Object {
        [PSCustomObject]@{
            Interface      = $_.InterfaceAlias
            IPv4Address    = ($_.IPv4Address.IPAddress -join ", ")
            DefaultGateway = ($_.IPv4DefaultGateway.NextHop -join ", ")
            DNSServers     = ($_.DNSServer.ServerAddresses -join ", ")
        }
    } |
    Format-Table -AutoSize

# ---------------------------------------------------------------------------
# 2. Gateway service and version
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "2. $($GatewayConfig.DisplayName) service and process information" -ForegroundColor Yellow

$gatewayServices = Get-CimInstance Win32_Service |
    Where-Object {
        $_.Name    -match $GatewayConfig.ServicePattern -or
        $_.DisplayName -match $GatewayConfig.ServicePattern
    }

$gatewayServices |
    Select-Object Name, DisplayName, State, ProcessId, PathName |
    Format-Table -AutoSize

if (Test-Path $GatewayConfig.ExecutablePath) {
    $version = (Get-Item $GatewayConfig.ExecutablePath).VersionInfo

    [PSCustomObject]@{
        ProductVersion   = $version.ProductVersion
        FileVersion      = $version.FileVersion
        RequiredMinimum  = $GatewayConfig.RequiredMinVersion
    } |
    Format-Table -AutoSize
}
else {
    Write-Warning "Could not locate gateway executable at: $($GatewayConfig.ExecutablePath)"
}

# ---------------------------------------------------------------------------
# 3. Workspace endpoint DNS, route, TCP, TLS and HTTP tests
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "3. Workspace-specific Fabric Private Link tests" -ForegroundColor Yellow

$endpointResults = foreach ($endpointName in $FabricEndpoints.Keys) {
    $endpoint = $FabricEndpoints[$endpointName]
    $hostname = $endpoint.Hostname
    $expectedIP = $endpoint.ExpectedIP

    Write-Host "Testing $endpointName : $hostname" -ForegroundColor DarkCyan

    $resolvedIPs = Resolve-IPv4Address -Hostname $hostname
    $dnsCorrect = $resolvedIPs -contains $expectedIP

    $routeNextHop = $null
    $routeInterface = $null

    try {
        $route = Find-NetRoute -RemoteIPAddress $expectedIP |
            Select-Object -First 1

        $routeNextHop = $route.NextHop
        $routeInterface = $route.InterfaceAlias
    }
    catch {
        $routeNextHop = "Unable to determine"
    }

    $tcpSuccess = Test-TcpPort -IPAddress $expectedIP -Port 443
    $tlsHttp = Test-TlsAndHttp -Hostname $hostname -IPAddress $expectedIP

    [PSCustomObject]@{
        Endpoint       = $endpointName
        Hostname       = $hostname
        ExpectedIP     = $expectedIP
        ResolvedIPs    = $resolvedIPs -join ", "
        DNSPrivate     = $dnsCorrect
        RouteInterface = $routeInterface
        NextHop        = $routeNextHop
        TCP443         = $tcpSuccess
        TLS            = $tlsHttp.TLS
        HTTP           = $tlsHttp.HTTPStatus
        Certificate    = $tlsHttp.CertificateSubject
        Error          = $tlsHttp.Error
    }
}

$endpointResults |
    Format-Table Endpoint, ExpectedIP, ResolvedIPs, DNSPrivate, TCP443, TLS, HTTP -AutoSize

Write-Host ""
Write-Host "Detailed endpoint results:" -ForegroundColor DarkCyan

$endpointResults |
    Format-List Endpoint, Hostname, ExpectedIP, ResolvedIPs,
                DNSPrivate, RouteInterface, NextHop, TCP443,
                TLS, HTTP, Certificate, Error

# ---------------------------------------------------------------------------
# 4. Global Fabric endpoint resolution
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "4. Global Fabric endpoint resolution" -ForegroundColor Yellow

$globalResults = foreach ($hostname in $GlobalEndpoints) {
    $resolved = Resolve-IPv4Address -Hostname $hostname

    [PSCustomObject]@{
        Hostname  = $hostname
        ResolvedIPs = $resolved -join ", "
        AllPrivate = (
            $resolved.Count -gt 0 -and
            (@($resolved | Where-Object { -not (Test-IsPrivateIPv4 $_) }).Count -eq 0)
        )
    }
}

$globalResults | Format-Table -AutoSize

Write-Host ""
Write-Host "Note: global Fabric endpoints resolving publicly is normal for" -ForegroundColor DarkYellow
Write-Host "workspace-level Private Link. The Lakehouse connector should use" -ForegroundColor DarkYellow
Write-Host "workspace-specific endpoints for workspace data operations." -ForegroundColor DarkYellow

# ---------------------------------------------------------------------------
# 5. Monitor actual SHIR connections during an ADF pipeline
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "5. Actual $($GatewayConfig.DisplayName) path monitoring" -ForegroundColor Yellow
Write-Host ""
Write-Host "This monitor will run for $MonitorSeconds seconds." -ForegroundColor Cyan
Write-Host "Monitoring processes: $($GatewayConfig.ProcessNames -join ', ')" -ForegroundColor Cyan
Write-Host "Start the pipeline/query immediately after pressing Enter." -ForegroundColor Cyan
Read-Host "Press Enter to begin monitoring"

$observedConnections = @{}
$monitorStart = Get-Date
$monitorEnd = $monitorStart.AddSeconds($MonitorSeconds)

while ((Get-Date) -lt $monitorEnd) {
    # Refresh the process list each iteration.
    $gatewayProcesses = Get-Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.ProcessName -in $GatewayConfig.ProcessNames
        }

    if ($gatewayProcesses) {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object {
                $_.OwningProcess -in $gatewayProcesses.Id -and
                $_.RemotePort -eq 443
            }

        foreach ($connection in $connections) {
            $process = $gatewayProcesses |
                Where-Object Id -eq $connection.OwningProcess |
                Select-Object -First 1

            $classification = "Public"

            if ($connection.RemoteAddress -in $FabricPrivateIPs) {
                $classification = "Fabric Private Link"
            }
            elseif (Test-IsPrivateIPv4 $connection.RemoteAddress) {
                $classification = "Other private"
            }

            $key = "{0}|{1}|{2}" -f `
                $process.ProcessName,
                $connection.RemoteAddress,
                $classification

            if (-not $observedConnections.ContainsKey($key)) {
                $observedConnections[$key] = [PSCustomObject]@{
                    FirstSeen      = Get-Date
                    LastSeen       = Get-Date
                    Process        = $process.ProcessName
                    PID            = $process.Id
                    RemoteAddress  = $connection.RemoteAddress
                    RemotePort     = $connection.RemotePort
                    Classification = $classification
                    Observations   = 1
                }
            }
            else {
                $observedConnections[$key].LastSeen = Get-Date
                $observedConnections[$key].Observations++
            }
        }
    }

    $remaining = [math]::Ceiling(($monitorEnd - (Get-Date)).TotalSeconds)
    Write-Progress `
        -Activity "Monitoring $GatewayType HTTPS connections" `
        -Status "$remaining seconds remaining" `
        -PercentComplete (
            (($MonitorSeconds - $remaining) / $MonitorSeconds) * 100
        )

    Start-Sleep -Milliseconds 250
}

Write-Progress -Activity "Monitoring $GatewayType HTTPS connections" -Completed

$connectionResults = @($observedConnections.Values) |
    Sort-Object Classification, RemoteAddress

Write-Host ""
Write-Host "Observed $GatewayType connections:" -ForegroundColor DarkCyan

$connectionResults |
    Format-Table FirstSeen, Process, PID, RemoteAddress,
                 RemotePort, Classification, Observations -AutoSize

# ---------------------------------------------------------------------------
# 6. DNS cache after the pipeline
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "6. Fabric-related DNS cache entries after the run" -ForegroundColor Yellow

$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Entry -match "fabric|onelake|datafactory|servicebus|microsoftonline"
    }

$dnsCache |
    Format-Table Entry, Data, Status, TimeToLive -AutoSize

# ---------------------------------------------------------------------------
# 7. Final assessment
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Final assessment" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$dnsFailures = @($endpointResults | Where-Object { -not $_.DNSPrivate })
$tcpFailures = @($endpointResults | Where-Object { -not $_.TCP443 })
$tlsFailures = @($endpointResults | Where-Object { -not $_.TLS })

$privateGatewayConnections = @(
    $connectionResults |
        Where-Object Classification -eq "Fabric Private Link"
)

$publicGatewayConnections = @(
    $connectionResults |
        Where-Object Classification -eq "Public"
)

if ($dnsFailures.Count -eq 0) {
    Write-Host "[PASS] All workspace endpoints resolve to expected private IPs." -ForegroundColor Green
}
else {
    Write-Host "[FAIL] One or more workspace endpoints have incorrect DNS." -ForegroundColor Red
}

if ($tcpFailures.Count -eq 0) {
    Write-Host "[PASS] TCP 443 is reachable on all Fabric private IPs." -ForegroundColor Green
}
else {
    Write-Host "[FAIL] TCP 443 failed for one or more private endpoints." -ForegroundColor Red
}

if ($tlsFailures.Count -eq 0) {
    Write-Host "[PASS] TLS/SNI succeeded through every Fabric private endpoint." -ForegroundColor Green
}
else {
    Write-Host "[FAIL] TLS/SNI failed for one or more Fabric endpoints." -ForegroundColor Red
}

if ($privateGatewayConnections.Count -gt 0) {
    Write-Host "[PASS] $GatewayType was observed using Fabric Private Link IPs." -ForegroundColor Green
}
else {
    Write-Host "[FAIL] $GatewayType was not observed connecting to Fabric Private Link IPs." -ForegroundColor Red
}

if ($publicGatewayConnections.Count -gt 0) {
    Write-Host "[INFO] $GatewayType also used public HTTPS destinations." -ForegroundColor Yellow
    Write-Host "       This can be normal for control-plane, Entra and Azure Relay traffic." -ForegroundColor Yellow
}
else {
    Write-Host "[INFO] No public HTTPS destinations observed for $GatewayType during the monitoring window." -ForegroundColor Green
}

Write-Host ""
Write-Host "Private Link is healthy only when DNS, TCP and TLS pass and $GatewayType is" -ForegroundColor Cyan
Write-Host "observed connecting to 10.151.0.144-10.151.0.148 during the pipeline/query." -ForegroundColor Cyan