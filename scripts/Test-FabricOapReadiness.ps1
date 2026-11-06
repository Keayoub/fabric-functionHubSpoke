#requires -Version 7.0
<#
.SYNOPSIS
    Inventories a Microsoft Fabric workspace for OAP readiness and creates
    both a readable Markdown report and a searchable, filterable HTML report.

.DESCRIPTION
    This script is read-only. It uses the Microsoft Fabric CLI (fab) to:
      - enumerate all Fabric items, following continuation tokens;
      - inventory Power BI dashboards and scorecards explicitly;
      - inventory Power BI reports and semantic models to assess whether an
        interactive report's semantic model is in the same workspace;
            - inspect capacity, outbound policy, and Git integration state;
            - report tenant, role, region, trial, and subscription prerequisites
                that require administrator confirmation;
      - classify items as Blocker, Attention, Supported, or Review;
      - write a navigable Markdown report and a self-contained interactive HTML
        report from the same in-memory result set.

    Exit codes:
      0 = no confirmed blocker, no unknown item type, and required checks passed
      1 = one or more confirmed OAP blockers found
    2 = review required because an item type is unknown or a required check failed or needs confirmation

    The classification is intentionally conservative. Unknown item types are
    marked Review rather than being incorrectly declared supported or blocked.

.PARAMETER WorkspaceId
    Fabric workspace GUID.

.PARAMETER MarkdownPath
    Output path for the Markdown report. Defaults to the current directory.

.PARAMETER HtmlPath
    Output path for the HTML report. Defaults to the Markdown path with .html.

.PARAMETER SkipHtml
    Create only the Markdown report. By default, both reports are created.

.EXAMPLE
    fab auth login
    ./Test-FabricOapReadiness.ps1 `
        -WorkspaceId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

.EXAMPLE
    ./Test-FabricOapReadiness.ps1 `
        -WorkspaceId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
        -MarkdownPath './reports/oap-readiness.md' `
        -HtmlPath './reports/oap-readiness.html'

.NOTES
    Requirements:
      - PowerShell 7+
      - Microsoft Fabric CLI: pip install --upgrade ms-fabric-cli
      - An authenticated fab session: fab auth login
      - Sufficient Fabric and Power BI read permissions for the workspace
            - Optional Azure CLI login to check Microsoft.Network provider status

    Documentation reviewed when this script was authored:
      https://learn.microsoft.com/fabric/security/workspace-outbound-access-protection-overview
      https://learn.microsoft.com/fabric/security/workspace-outbound-access-protection-power-bi-reports
      https://learn.microsoft.com/fabric/security/workspace-outbound-access-protection-paginated-reports
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid] $WorkspaceId,

    [string] $MarkdownPath,

    [string] $HtmlPath,

    [switch] $SkipHtml
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:OapOverviewUrl = 'https://learn.microsoft.com/fabric/security/workspace-outbound-access-protection-overview'
$script:OapReportsUrl = 'https://learn.microsoft.com/fabric/security/workspace-outbound-access-protection-power-bi-reports'
$script:OapPaginatedReportsUrl = 'https://learn.microsoft.com/fabric/security/workspace-outbound-access-protection-paginated-reports'
$script:OapSetupUrl = 'https://learn.microsoft.com/fabric/security/workspace-outbound-access-protection-set-up'
$script:OapAvailabilityUrl = 'https://learn.microsoft.com/fabric/security/security-feature-availability'

if (-not (Get-Command fab -ErrorAction SilentlyContinue)) {
    throw 'Microsoft Fabric CLI (fab) was not found. Install it with: pip install --upgrade ms-fabric-cli'
}

if ([string]::IsNullOrWhiteSpace($MarkdownPath)) {
    $MarkdownPath = Join-Path `
        -Path (Get-Location) `
        -ChildPath "Fabric-OAP-Readiness-$WorkspaceId.md"
}

$MarkdownPath = [System.IO.Path]::GetFullPath($MarkdownPath)

if (-not $SkipHtml -and [string]::IsNullOrWhiteSpace($HtmlPath)) {
    $HtmlPath = [System.IO.Path]::ChangeExtension($MarkdownPath, '.html')
}
elseif (-not [string]::IsNullOrWhiteSpace($HtmlPath)) {
    $HtmlPath = [System.IO.Path]::GetFullPath($HtmlPath)
}

$outputPaths = @($MarkdownPath)
if (-not $SkipHtml) {
    $outputPaths += $HtmlPath
}

foreach ($path in $outputPaths) {
    $directory = Split-Path -Parent $path
    if (-not [string]::IsNullOrWhiteSpace($directory) -and
        -not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }
}

function Get-PropertyValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object] $InputObject,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function ConvertFrom-PossibleJson {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object] $Value
    )

    if ($Value -isnot [string]) {
        return $Value
    }

    $trimmed = $Value.Trim()
    if (($trimmed.StartsWith('{') -and $trimmed.EndsWith('}')) -or
        ($trimmed.StartsWith('[') -and $trimmed.EndsWith(']'))) {
        try {
            return $trimmed | ConvertFrom-Json -Depth 100
        }
        catch {
            return $Value
        }
    }

    return $Value
}

function Invoke-FabApiJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Endpoint,

        [ValidateSet('fabric', 'powerbi')]
        [string] $Audience = 'fabric'
    )

    $stdoutPath = [System.IO.Path]::GetTempFileName()
    $stderrPath = [System.IO.Path]::GetTempFileName()

    try {
        $arguments = @(
            'api',
            '-A', $Audience,
            '-X', 'get',
            $Endpoint,
            '--output_format', 'json'
        )

        & fab @arguments 1> $stdoutPath 2> $stderrPath
        $exitCode = $LASTEXITCODE
        $stdout = Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue
        $stderr = Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue

        if ($exitCode -ne 0) {
            $detail = @($stdout, $stderr) |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { $_.Trim() }
            throw "fab api failed for '$Endpoint' (exit code $exitCode): $($detail -join ' | ')"
        }

        if ([string]::IsNullOrWhiteSpace($stdout)) {
            throw "fab api returned no JSON output for '$Endpoint'. stderr: $stderr"
        }

        try {
            $envelope = $stdout | ConvertFrom-Json -Depth 100
        }
        catch {
            throw "fab api returned invalid JSON for '$Endpoint': $stdout"
        }

        $status = [string] (Get-PropertyValue -InputObject $envelope -Name 'status')
        if (-not [string]::IsNullOrWhiteSpace($status) -and $status -ne 'Success') {
            $result = Get-PropertyValue -InputObject $envelope -Name 'result'
            $message = [string] (Get-PropertyValue -InputObject $result -Name 'message')
            if ([string]::IsNullOrWhiteSpace($message)) {
                $message = $stdout
            }
            throw "fab api reported failure for '$Endpoint': $message"
        }

        $resultObject = Get-PropertyValue -InputObject $envelope -Name 'result'
        if ($null -eq $resultObject) {
            throw "fab api JSON for '$Endpoint' did not contain a result object."
        }

        $dataProperty = $resultObject.PSObject.Properties['data']
        if ($null -eq $dataProperty) {
            throw "fab api JSON for '$Endpoint' did not contain result.data."
        }

        $parsedData = ConvertFrom-PossibleJson -Value $dataProperty.Value
        $transportResponse = $parsedData
        if ($parsedData -is [array] -and $parsedData.Count -eq 1) {
            $transportResponse = $parsedData[0]
        }

        $statusCode = Get-PropertyValue -InputObject $transportResponse -Name 'status_code'
        $responseText = Get-PropertyValue -InputObject $transportResponse -Name 'text'
        if ($null -ne $statusCode -and $null -ne $responseText) {
            if ([int] $statusCode -lt 200 -or [int] $statusCode -ge 300) {
                throw "fab api returned HTTP status $statusCode for '$Endpoint'."
            }

            $valueProperty = $responseText.PSObject.Properties['value']
            if ($null -ne $valueProperty) {
                if ($Endpoint -match '(?:^|/)(?:items|dashboards|scorecards|reports|datasets)(?:\?|$)') {
                    return $responseText
                }

                $responseValue = $valueProperty.Value
                if ($responseValue -is [array] -and $responseValue.Count -eq 1) {
                    return $responseValue[0]
                }

                return $responseValue
            }

            return ConvertFrom-PossibleJson -Value $responseText
        }

        return $parsedData
    }
    finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-ApiCollection {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object] $Response,

        [string] $PropertyName = 'value'
    )

    if ($null -eq $Response) {
        return @()
    }

    if ($Response -is [array]) {
        return @($Response)
    }

    $property = $Response.PSObject.Properties[$PropertyName]
    if ($null -ne $property) {
        return @($property.Value)
    }

    throw "API response did not contain the expected '$PropertyName' collection."
}

function ConvertTo-PowerBiEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $NextLink
    )

    $prefix = 'https://api.powerbi.com/v1.0/myorg/'
    if ($NextLink.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $NextLink.Substring($prefix.Length)
    }

    return $NextLink
}

function Get-PowerBiCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Endpoint
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $seenLinks = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $nextEndpoint = $Endpoint

    while (-not [string]::IsNullOrWhiteSpace($nextEndpoint)) {
        if (-not $seenLinks.Add($nextEndpoint)) {
            throw "The Power BI API repeated a continuation link for '$Endpoint'."
        }

        $response = Invoke-FabApiJson -Endpoint $nextEndpoint -Audience 'powerbi'
        foreach ($entry in (Get-ApiCollection -Response $response)) {
            $results.Add($entry)
        }

        $nextLink = [string] (Get-PropertyValue -InputObject $response -Name '@odata.nextLink')
        if ([string]::IsNullOrWhiteSpace($nextLink)) {
            $nextEndpoint = $null
        }
        else {
            $nextEndpoint = ConvertTo-PowerBiEndpoint -NextLink $nextLink
        }
    }

    return $results.ToArray()
}

function New-InventoryItem {
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string] $Name,

        [AllowEmptyString()]
        [string] $Type,

        [AllowEmptyString()]
        [string] $Id,

        [Parameter(Mandatory)]
        [string] $Source,

        [AllowEmptyString()]
        [string] $WebUrl,

        [AllowEmptyString()]
        [string] $DatasetId,

        [AllowEmptyString()]
        [string] $ReportType,

        [AllowEmptyString()]
        [string] $Details
    )

    return [pscustomobject]@{
        Name          = $Name
        Type          = $Type
        Id            = $Id
        Source        = $Source
        WebUrl        = $WebUrl
        DatasetId     = $DatasetId
        ReportType    = $ReportType
        Details       = $Details
        BindingStatus = ''
        Status        = ''
        Reason        = ''
        SortRank      = 99
    }
}

function Add-CheckResult {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[object]] $List,

        [Parameter(Mandatory)]
        [string] $Check,

        [ValidateSet('Passed', 'Warning', 'Failed')]
        [string] $Status,

        [Parameter(Mandatory)]
        [string] $Detail,

        [bool] $RequiredForReadiness
    )

    $List.Add([pscustomobject]@{
        Check                = $Check
        Status               = $Status
        Detail               = $Detail
        RequiredForReadiness = $RequiredForReadiness
    })
}

function Normalize-ItemType {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object] $Type
    )

    if ($null -eq $Type) {
        return ''
    }

    return ([string] $Type).ToLowerInvariant() -replace '[^a-z0-9]', ''
}

function Set-OapAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Item,

        [AllowEmptyCollection()]
        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[string]] $WorkspaceDatasetIds,

        [bool] $DatasetInventoryComplete
    )

    $normalizedType = Normalize-ItemType -Type $Item.Type
    $unsupportedTypeReasons = @{
        'apacheairflowjob' = 'Data Workflow (previously Apache Airflow) is listed as unsupported for OAP in the Fabric security feature availability matrix.'
        'dataworkflow'     = 'Data Workflow (previously Apache Airflow) is listed as unsupported for OAP in the Fabric security feature availability matrix.'
        'ontology'         = 'Ontology is listed as unsupported for OAP in the Fabric security feature availability matrix.'
        'sqldatabase'      = 'SQL database in Fabric is listed as unsupported for OAP in the Fabric security feature availability matrix.'
    }

    if ($unsupportedTypeReasons.ContainsKey($normalizedType)) {
        $Item.Status = 'Blocker'
        $Item.Reason = $unsupportedTypeReasons[$normalizedType]
        $Item.SortRank = 1
        return
    }

    switch ($normalizedType) {
        'dashboard' {
            $Item.Status = 'Blocker'
            $Item.Reason = 'Power BI dashboards are not supported in OAP-protected workspaces.'
            $Item.SortRank = 1
            return
        }
        'scorecard' {
            $Item.Status = 'Blocker'
            $Item.Reason = 'Power BI scorecards are not supported in OAP-protected workspaces.'
            $Item.SortRank = 1
            return
        }
        'metrics' {
            $Item.Status = 'Blocker'
            $Item.Reason = 'This item is treated as a Power BI scorecard/metrics artifact, which is not supported in OAP-protected workspaces.'
            $Item.SortRank = 1
            return
        }
        'report' {
            if ([string]::Equals($Item.ReportType, 'PaginatedReport', [System.StringComparison]::OrdinalIgnoreCase)) {
                $Item.Type = 'PaginatedReport'
                Set-OapAssessment `
                    -Item $Item `
                    -WorkspaceDatasetIds $WorkspaceDatasetIds `
                    -DatasetInventoryComplete $DatasetInventoryComplete
                return
            }

            if (-not $DatasetInventoryComplete) {
                $Item.BindingStatus = 'Not verified'
                $Item.Status = 'Attention'
                $Item.Reason = 'Interactive reports are supported, but the semantic-model inventory failed, so same-workspace binding could not be verified.'
                $Item.SortRank = 2
                return
            }

            if ([string]::IsNullOrWhiteSpace($Item.DatasetId)) {
                $Item.BindingStatus = 'Unknown'
                $Item.Status = 'Attention'
                $Item.Reason = 'Interactive reports are supported only when bound to a semantic model in the same workspace; this report returned no dataset ID.'
                $Item.SortRank = 2
                return
            }

            if ($WorkspaceDatasetIds.Contains($Item.DatasetId)) {
                $Item.BindingStatus = 'Same workspace'
                $Item.Status = 'Supported'
                $Item.Reason = 'Interactive report with a semantic model found in this workspace.'
                $Item.SortRank = 3
                return
            }

            $Item.BindingStatus = 'Cross-workspace or inaccessible model'
            $Item.Status = 'Attention'
            $Item.Reason = 'Interactive reports can remain, but this report appears bound to a semantic model outside the workspace or one that was not visible to the inventory. It will not query that model after OAP is enabled.'
            $Item.SortRank = 2
            return
        }
        'powerbireport' {
            $Item.Type = 'Report'
            Set-OapAssessment `
                -Item $Item `
                -WorkspaceDatasetIds $WorkspaceDatasetIds `
                -DatasetInventoryComplete $DatasetInventoryComplete
            return
        }
        'paginatedreport' {
            $Item.Status = 'Attention'
            $Item.Reason = 'Paginated reports are supported, but their data sources, maps, external images, and semantic-model connections require the appropriate OAP data connection rules. AIXL model connections should be converted to XMLA.'
            $Item.SortRank = 2
            return
        }
        'semanticmodel' {
            $Item.Status = 'Attention'
            $Item.Reason = 'Semantic models are supported; configure and test the required data connection rules for their sources.'
            $Item.SortRank = 2
            return
        }
        'dataset' {
            $Item.Type = 'SemanticModel'
            $Item.Status = 'Attention'
            $Item.Reason = 'Semantic models are supported; configure and test the required data connection rules for their sources.'
            $Item.SortRank = 2
            return
        }
        'dataflow' {
            $Item.Status = 'Attention'
            $Item.Reason = 'Dataflow Gen2 is supported with CI/CD. Confirm this item is the supported Dataflow Gen2 variant and validate its data connection rules.'
            $Item.SortRank = 2
            return
        }
        'dataflowgen2' {
            $Item.Status = 'Attention'
            $Item.Reason = 'Dataflow Gen2 is supported with CI/CD; validate its data connection rules.'
            $Item.SortRank = 2
            return
        }
    }

    $supportedTypes = @(
        'lakehouse',
        'notebook',
        'sparkjobdefinition',
        'graphmodel',
        'kqldatabase',
        'plan',
        'variablelibrary',
        'environment',
        'pipeline',
        'datapipeline',
        'copyjob',
        'mlexperiment',
        'machinelearningexperiment',
        'mlmodel',
        'machinelearningmodel',
        'warehouse',
        'sqlendpoint',
        'sqlanalyticsendpoint',
        'graph',
        'operationsagent',
        'dataagent',
        'activator',
        'eventstream',
        'eventhouse',
        'fabricmap',
        'mirroreddatabase',
        'mirroreddatabases',
        'azureevent',
        'fabricevent',
        'businessevent'
    )

    if ($normalizedType -in $supportedTypes) {
        $Item.Status = 'Supported'
        $Item.Reason = 'This item type is listed as supported for workspace OAP. Its connections and workload-specific limitations still require validation.'
        $Item.SortRank = 3
        return
    }

    $Item.Status = 'Review'
    $Item.Reason = 'This item type is not recognized by this script. Compare it with the current Microsoft OAP supported-item documentation before enabling OAP.'
    $Item.SortRank = 4
}

function ConvertTo-MarkdownCell {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object] $Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string] $Value)) {
        return '-'
    }

    $text = [string] $Value
    $text = $text.Replace('\', '\\')
    $text = $text.Replace('|', '\|')
    $text = $text.Replace('[', '\[')
    $text = $text.Replace(']', '\]')
    $text = $text.Replace("`r", ' ')
    $text = $text.Replace("`n", ' ')
    $text = $text.Replace('`', '\`')
    return $text
}

function ConvertTo-HtmlText {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object] $Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode([string] $Value)
}

function ConvertTo-RelativeReportLink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $FromPath,

        [Parameter(Mandatory)]
        [string] $ToPath
    )

    $fromDirectory = Split-Path -Parent $FromPath
    $relative = [System.IO.Path]::GetRelativePath($fromDirectory, $ToPath)
    return $relative.Replace([System.IO.Path]::DirectorySeparatorChar, '/')
}

$rawItems = [System.Collections.Generic.List[object]]::new()
$checks = [System.Collections.Generic.List[object]]::new()
$workspace = $null
$capacityAzureResourceId = ''
$workspaceName = ''
$fabricInventoryComplete = $false
$dashboardInventoryComplete = $false
$scorecardInventoryComplete = $false
$reportInventoryComplete = $false
$datasetInventoryComplete = $false

Write-Host "Inspecting Fabric workspace $WorkspaceId..." -ForegroundColor Cyan

# Workspace metadata is useful for the report but is not required for readiness.
try {
    $workspace = Invoke-FabApiJson -Endpoint "workspaces/$WorkspaceId"
    $workspaceName = [string] (Get-PropertyValue -InputObject $workspace -Name 'displayName')
    if ([string]::IsNullOrWhiteSpace($workspaceName)) {
        $workspaceName = [string] (Get-PropertyValue -InputObject $workspace -Name 'name')
    }
    Add-CheckResult `
        -List $checks `
        -Check 'Workspace metadata' `
        -Status 'Passed' `
        -Detail 'Workspace metadata retrieved.' `
        -RequiredForReadiness $false
}
catch {
    Add-CheckResult `
        -List $checks `
        -Check 'Workspace metadata' `
        -Status 'Warning' `
        -Detail $_.Exception.Message `
        -RequiredForReadiness $false
}

# Workspace eligibility checks that can be read from Fabric APIs.
$capacityId = [string] (Get-PropertyValue -InputObject $workspace -Name 'capacityId')
$capacityRegion = [string] (Get-PropertyValue -InputObject $workspace -Name 'capacityRegion')
if ([string]::IsNullOrWhiteSpace($capacityId)) {
    Add-CheckResult `
        -List $checks `
        -Check 'Fabric capacity eligibility' `
        -Status 'Failed' `
        -Detail 'The workspace metadata did not include a Fabric capacity assignment. OAP requires a supported Fabric F SKU.' `
        -RequiredForReadiness $true
}
else {
    try {
        $capacity = Invoke-FabApiJson -Endpoint "capacities/$capacityId"
        $capacitySku = [string] (Get-PropertyValue -InputObject $capacity -Name 'sku')
        $capacityState = [string] (Get-PropertyValue -InputObject $capacity -Name 'state')
        $capacityAzureResourceId = [string] (Get-PropertyValue -InputObject $capacity -Name 'azureResourceId')
        $capacityEligible = $capacitySku -match '^F\d+$' -and $capacityState -eq 'Active'
        $capacityStatus = if ($capacityEligible) { 'Passed' } else { 'Failed' }
        Add-CheckResult `
            -List $checks `
            -Check 'Fabric capacity eligibility' `
            -Status $capacityStatus `
            -Detail "Capacity '$($capacity.displayName)' reports SKU '$capacitySku' and state '$capacityState'. OAP requires an active Fabric F SKU; F SKU trials are not supported." `
            -RequiredForReadiness $true
    }
    catch {
        Add-CheckResult `
            -List $checks `
            -Check 'Fabric capacity eligibility' `
            -Status 'Warning' `
            -Detail "Could not verify capacity '$capacityId': $($_.Exception.Message) Confirm that the workspace is on an active, non-trial Fabric F SKU." `
            -RequiredForReadiness $true
    }
}

Add-CheckResult `
    -List $checks `
    -Check 'F SKU trial status' `
    -Status 'Warning' `
    -Detail 'Fabric capacity metadata does not identify trial status. Confirm this is not an F SKU trial; trials are not supported for OAP.' `
    -RequiredForReadiness $true

if ([string]::IsNullOrWhiteSpace($capacityRegion)) {
    Add-CheckResult `
        -List $checks `
        -Check 'Capacity region support' `
        -Status 'Warning' `
        -Detail 'The workspace metadata did not include a capacity region. Verify that the assigned capacity region supports Fabric Data Engineering workloads.' `
        -RequiredForReadiness $true
}
else {
    Add-CheckResult `
        -List $checks `
        -Check 'Capacity region support' `
        -Status 'Warning' `
        -Detail "The workspace capacity region is '$capacityRegion'. Confirm this region currently supports Fabric Data Engineering workloads for OAP." `
        -RequiredForReadiness $true
}

foreach ($manualPrerequisite in @(
    @{
        Check = 'Tenant outbound network rules setting'
        Detail = 'Confirm a Fabric tenant administrator has enabled "Configure workspace-level outbound network rules".'
    },
    @{
        Check = 'Workspace Admin role'
        Detail = 'Confirm the account enabling OAP has the Admin role in this workspace.'
    }
)) {
    Add-CheckResult `
        -List $checks `
        -Check $manualPrerequisite.Check `
        -Status 'Warning' `
        -Detail $manualPrerequisite.Detail `
        -RequiredForReadiness $true
}

try {
    $communicationPolicy = Invoke-FabApiJson -Endpoint "workspaces/$WorkspaceId/networking/communicationPolicy"
    $outbound = Get-PropertyValue -InputObject $communicationPolicy -Name 'outbound'
    $publicAccessRules = Get-PropertyValue -InputObject $outbound -Name 'publicAccessRules'
    $outboundAction = [string] (Get-PropertyValue -InputObject $publicAccessRules -Name 'defaultAction')
    $policyStatus = if ($outboundAction -eq 'Deny') { 'Passed' } else { 'Warning' }
    $policyDetail = if ($outboundAction -eq 'Deny') {
        'The current workspace policy denies public outbound access; OAP is already enabled.'
    }
    else {
        "The current outbound default action is '$outboundAction'; OAP is not currently enabled. This check does not reveal why the portal may disable the toggle."
    }
    Add-CheckResult `
        -List $checks `
        -Check 'Current outbound access policy' `
        -Status $policyStatus `
        -Detail $policyDetail `
        -RequiredForReadiness $false
}
catch {
    Add-CheckResult `
        -List $checks `
        -Check 'Current outbound access policy' `
        -Status 'Warning' `
        -Detail "Could not read the workspace network policy: $($_.Exception.Message)" `
        -RequiredForReadiness $false
}

try {
    $gitStatus = Invoke-FabApiJson -Endpoint "workspaces/$WorkspaceId/git/status"
    $workspaceHead = [string] (Get-PropertyValue -InputObject $gitStatus -Name 'workspaceHead')
    $remoteCommitHash = [string] (Get-PropertyValue -InputObject $gitStatus -Name 'remoteCommitHash')
    $gitConnected = -not [string]::IsNullOrWhiteSpace($workspaceHead) -or
        -not [string]::IsNullOrWhiteSpace($remoteCommitHash)
    $gitCheckStatus = if ($gitConnected) { 'Warning' } else { 'Passed' }
    $gitDetail = if ($gitConnected) {
        'A Git connection is configured. Git integration is blocked by default after OAP is enabled; turn on Allow Git integration in the workspace network settings if synchronization must continue. This does not by itself block enabling OAP.'
    }
    else {
        'No active Git connection was reported for this workspace.'
    }
    Add-CheckResult `
        -List $checks `
        -Check 'Git integration compatibility' `
        -Status $gitCheckStatus `
        -Detail $gitDetail `
        -RequiredForReadiness $false
}
catch {
    Add-CheckResult `
        -List $checks `
        -Check 'Git integration compatibility' `
        -Status 'Warning' `
        -Detail "Could not inspect Git integration state: $($_.Exception.Message) Verify the connection manually; Git is blocked by default after OAP is enabled unless allowed in workspace network settings." `
        -RequiredForReadiness $false
}

if ((Get-Command az -ErrorAction SilentlyContinue) -and
    $capacityAzureResourceId -match '^/subscriptions/([^/]+)/') {
    $capacitySubscriptionId = $Matches[1]
    try {
        $providerState = (& az provider show --namespace Microsoft.Network --subscription $capacitySubscriptionId --query registrationState --output tsv 2>$null | Out-String).Trim()
        if ($LASTEXITCODE -eq 0 -and $providerState -eq 'Registered') {
            Add-CheckResult `
                -List $checks `
                -Check 'Microsoft.Network provider registration' `
                -Status 'Passed' `
                -Detail "Microsoft.Network is registered in the Azure subscription associated with the Fabric capacity." `
                -RequiredForReadiness $true
        }
        elseif ($LASTEXITCODE -eq 0) {
            Add-CheckResult `
                -List $checks `
                -Check 'Microsoft.Network provider registration' `
                -Status 'Failed' `
                -Detail "Microsoft.Network registration state is '$providerState' in the Azure subscription associated with the Fabric capacity. Register the provider if appropriate." `
                -RequiredForReadiness $true
        }
            elseif ($LASTEXITCODE -ne 0) {
                Add-CheckResult `
                    -List $checks `
                    -Check 'Microsoft.Network provider registration' `
                    -Status 'Warning' `
                    -Detail "Azure CLI could not verify Microsoft.Network registration for capacity subscription '$capacitySubscriptionId'. Confirm the provider state manually." `
                    -RequiredForReadiness $true
            }
    }
    catch {
        Add-CheckResult `
            -List $checks `
            -Check 'Microsoft.Network provider registration' `
            -Status 'Warning' `
            -Detail "Azure CLI could not verify Microsoft.Network registration: $($_.Exception.Message) Confirm the provider in the capacity's subscription." `
            -RequiredForReadiness $true
    }
}
    else {
        Add-CheckResult `
            -List $checks `
            -Check 'Microsoft.Network provider registration' `
            -Status 'Warning' `
            -Detail 'Azure CLI or the capacity Azure resource ID is unavailable; confirm Microsoft.Network is registered in the Azure subscription associated with this capacity.' `
            -RequiredForReadiness $true
    }

# Fabric item inventory with continuation tokens.
try {
    $token = $null
    $seenTokens = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )

    do {
        $endpoint = "workspaces/$WorkspaceId/items"
        if (-not [string]::IsNullOrWhiteSpace($token)) {
            if (-not $seenTokens.Add($token)) {
                throw 'The Fabric items API repeated a continuation token.'
            }
            $encodedToken = [System.Uri]::EscapeDataString($token)
            $endpoint += "?continuationToken=$encodedToken"
        }

        $response = Invoke-FabApiJson -Endpoint $endpoint
        foreach ($item in (Get-ApiCollection -Response $response)) {
            $rawItems.Add((New-InventoryItem `
                -Name ([string] (Get-PropertyValue -InputObject $item -Name 'displayName')) `
                -Type ([string] (Get-PropertyValue -InputObject $item -Name 'type')) `
                -Id ([string] (Get-PropertyValue -InputObject $item -Name 'id')) `
                -Source 'Fabric items API'))
        }

        $token = [string] (Get-PropertyValue -InputObject $response -Name 'continuationToken')
    }
    while (-not [string]::IsNullOrWhiteSpace($token))

    $fabricInventoryComplete = $true
    Add-CheckResult `
        -List $checks `
        -Check 'Fabric item inventory' `
        -Status 'Passed' `
        -Detail 'All continuation pages were retrieved.' `
        -RequiredForReadiness $true
}
catch {
    Add-CheckResult `
        -List $checks `
        -Check 'Fabric item inventory' `
        -Status 'Failed' `
        -Detail $_.Exception.Message `
        -RequiredForReadiness $true
}

# Power BI dashboards: confirmed OAP blockers.
try {
    $dashboards = @(Get-PowerBiCollection -Endpoint "groups/$WorkspaceId/dashboards")
    foreach ($dashboard in $dashboards) {
        $rawItems.Add((New-InventoryItem `
            -Name ([string] (Get-PropertyValue -InputObject $dashboard -Name 'displayName')) `
            -Type 'Dashboard' `
            -Id ([string] (Get-PropertyValue -InputObject $dashboard -Name 'id')) `
            -Source 'Power BI dashboards API' `
            -WebUrl ([string] (Get-PropertyValue -InputObject $dashboard -Name 'webUrl'))))
    }

    $dashboardInventoryComplete = $true
    Add-CheckResult `
        -List $checks `
        -Check 'Power BI dashboard inventory' `
        -Status 'Passed' `
        -Detail "$($dashboards.Count) dashboard(s) returned." `
        -RequiredForReadiness $true
}
catch {
    Add-CheckResult `
        -List $checks `
        -Check 'Power BI dashboard inventory' `
        -Status 'Failed' `
        -Detail $_.Exception.Message `
        -RequiredForReadiness $true
}

# Power BI scorecards: confirmed OAP blockers.
try {
    $scorecards = @(Get-PowerBiCollection -Endpoint "groups/$WorkspaceId/scorecards")
    foreach ($scorecard in $scorecards) {
        $rawItems.Add((New-InventoryItem `
            -Name ([string] (Get-PropertyValue -InputObject $scorecard -Name 'name')) `
            -Type 'Scorecard' `
            -Id ([string] (Get-PropertyValue -InputObject $scorecard -Name 'id')) `
            -Source 'Power BI scorecards API' `
            -DatasetId ([string] (Get-PropertyValue -InputObject $scorecard -Name 'datasetId')) `
            -Details 'Power BI scorecard/metrics artifact'))
    }

    $scorecardInventoryComplete = $true
    Add-CheckResult `
        -List $checks `
        -Check 'Power BI scorecard inventory' `
        -Status 'Passed' `
        -Detail "$($scorecards.Count) scorecard(s) returned." `
        -RequiredForReadiness $true
}
catch {
    Add-CheckResult `
        -List $checks `
        -Check 'Power BI scorecard inventory' `
        -Status 'Failed' `
        -Detail $_.Exception.Message `
        -RequiredForReadiness $true
}

# Power BI reports: used to identify report types and model bindings.
try {
    $reports = @(Get-PowerBiCollection -Endpoint "groups/$WorkspaceId/reports")
    foreach ($report in $reports) {
        $reportType = [string] (Get-PropertyValue -InputObject $report -Name 'reportType')
        $itemType = if ([string]::Equals(
            $reportType,
            'PaginatedReport',
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            'PaginatedReport'
        }
        else {
            'Report'
        }

        $rawItems.Add((New-InventoryItem `
            -Name ([string] (Get-PropertyValue -InputObject $report -Name 'name')) `
            -Type $itemType `
            -Id ([string] (Get-PropertyValue -InputObject $report -Name 'id')) `
            -Source 'Power BI reports API' `
            -WebUrl ([string] (Get-PropertyValue -InputObject $report -Name 'webUrl')) `
            -DatasetId ([string] (Get-PropertyValue -InputObject $report -Name 'datasetId')) `
            -ReportType $reportType))
    }

    $reportInventoryComplete = $true
    Add-CheckResult `
        -List $checks `
        -Check 'Power BI report inventory' `
        -Status 'Passed' `
        -Detail "$($reports.Count) report(s) returned; report-to-model bindings can be assessed when the semantic-model inventory also succeeds." `
        -RequiredForReadiness $true
}
catch {
    Add-CheckResult `
        -List $checks `
        -Check 'Power BI report inventory' `
        -Status 'Failed' `
        -Detail $_.Exception.Message `
        -RequiredForReadiness $true
}

# Power BI semantic models (datasets): used for same-workspace binding checks.
try {
    $datasets = @(Get-PowerBiCollection -Endpoint "groups/$WorkspaceId/datasets")
    foreach ($dataset in $datasets) {
        $rawItems.Add((New-InventoryItem `
            -Name ([string] (Get-PropertyValue -InputObject $dataset -Name 'name')) `
            -Type 'SemanticModel' `
            -Id ([string] (Get-PropertyValue -InputObject $dataset -Name 'id')) `
            -Source 'Power BI datasets API'))
    }

    $datasetInventoryComplete = $true
    Add-CheckResult `
        -List $checks `
        -Check 'Power BI semantic-model inventory' `
        -Status 'Passed' `
        -Detail "$($datasets.Count) semantic model(s) returned." `
        -RequiredForReadiness $true
}
catch {
    Add-CheckResult `
        -List $checks `
        -Check 'Power BI semantic-model inventory' `
        -Status 'Failed' `
        -Detail $_.Exception.Message `
        -RequiredForReadiness $true
}

# Deduplicate records that appear in both Fabric and Power BI inventories. Prefer
# the richest record while retaining all source names.
$uniqueItems = [System.Collections.Generic.List[object]]::new()
$groups = $rawItems | Group-Object -Property {
    if (-not [string]::IsNullOrWhiteSpace($_.Id)) {
        return "id:$($_.Id.ToLowerInvariant())"
    }
    return "name:$((Normalize-ItemType $_.Type)):$($_.Name.ToLowerInvariant())"
}

foreach ($group in $groups) {
    $members = @($group.Group)
    $preferred = $members |
        Sort-Object `
            @{ Expression = { [string]::IsNullOrWhiteSpace($_.DatasetId) } }, `
            @{ Expression = { [string]::IsNullOrWhiteSpace($_.WebUrl) } }, `
            @{ Expression = { [string]::IsNullOrWhiteSpace($_.ReportType) } } |
        Select-Object -First 1

    $sources = @($members.Source | Sort-Object -Unique) -join '; '
    $types = @($members.Type | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $preferredType = if ($types -contains 'PaginatedReport') {
        'PaginatedReport'
    }
    elseif ($types -contains 'Report') {
        'Report'
    }
    elseif ($types -contains 'SemanticModel') {
        'SemanticModel'
    }
    else {
        [string] $preferred.Type
    }

    $uniqueItems.Add((New-InventoryItem `
        -Name ([string] $preferred.Name) `
        -Type $preferredType `
        -Id ([string] $preferred.Id) `
        -Source $sources `
        -WebUrl ([string] $preferred.WebUrl) `
        -DatasetId ([string] $preferred.DatasetId) `
        -ReportType ([string] $preferred.ReportType) `
        -Details ([string] $preferred.Details)))
}

$workspaceDatasetIds = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
foreach ($dataset in ($uniqueItems | Where-Object { (Normalize-ItemType $_.Type) -eq 'semanticmodel' })) {
    if (-not [string]::IsNullOrWhiteSpace($dataset.Id)) {
        $null = $workspaceDatasetIds.Add($dataset.Id)
    }
}

foreach ($item in $uniqueItems) {
    Set-OapAssessment `
        -Item $item `
        -WorkspaceDatasetIds $workspaceDatasetIds `
        -DatasetInventoryComplete $datasetInventoryComplete
}

$orderedItems = @(
    $uniqueItems |
        Sort-Object SortRank, Type, Name, Id
)

$reportBindingItems = @(
    $orderedItems | Where-Object { (Normalize-ItemType $_.Type) -eq 'report' }
)
$blockers = @($orderedItems | Where-Object { $_.Status -eq 'Blocker' })
$attention = @($orderedItems | Where-Object { $_.Status -eq 'Attention' })
$supported = @($orderedItems | Where-Object { $_.Status -eq 'Supported' })
$review = @($orderedItems | Where-Object { $_.Status -eq 'Review' })
$requiredChecksNeedingConfirmation = @(
    $checks | Where-Object {
        $_.RequiredForReadiness -and $_.Status -ne 'Passed'
    }
)

if ($blockers.Count -gt 0) {
    $overallStatus = 'Blocked'
    $overallSummary = 'Confirmed OAP item blocker(s) found.'
    $overallIcon = '⛔'
}
elseif ($review.Count -gt 0 -or $requiredChecksNeedingConfirmation.Count -gt 0) {
    $overallStatus = 'Review required'
    $overallSummary = 'Readiness needs review because an item type is unclassified or a required OAP preflight/inventory check failed or still needs confirmation.'
    $overallIcon = '⚠️'
}
elseif ($attention.Count -gt 0) {
    $overallStatus = 'No item-type blocker found; configuration attention remains'
    $overallSummary = 'No confirmed item-type blocker was found, but supported items still require configuration or binding validation.'
    $overallIcon = '🟡'
}
else {
    $overallStatus = 'No item-type blocker found'
    $overallSummary = 'No confirmed OAP item-type blocker was found by the completed checks.'
    $overallIcon = '✅'
}

$generatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss ''UTC''')
$workspaceLabel = if ([string]::IsNullOrWhiteSpace($workspaceName)) {
    [string] $WorkspaceId
}
else {
    "$workspaceName ($WorkspaceId)"
}

# --------------------------- Markdown report ---------------------------
$markdown = [System.Collections.Generic.List[string]]::new()
$markdown.Add('# Fabric workspace OAP readiness report')
$markdown.Add('')
$markdown.Add("> **$overallIcon $overallStatus** — $overallSummary")
$markdown.Add('')
$markdown.Add("- **Workspace:** $(ConvertTo-MarkdownCell $workspaceLabel)")
$markdown.Add("- **Generated:** $generatedUtc")
$markdown.Add("- **Items inventoried:** $($orderedItems.Count)")
$markdown.Add("- **Confirmed blockers:** $($blockers.Count)")
$markdown.Add("- **Configuration attention:** $($attention.Count)")
$markdown.Add("- **Unknown types to review:** $($review.Count)")
$markdown.Add('')

if (-not $SkipHtml) {
    $relativeHtmlPath = ConvertTo-RelativeReportLink -FromPath $MarkdownPath -ToPath $HtmlPath
    $markdown.Add("**[Open the interactive report]($relativeHtmlPath)** for live search, filters, sorting, and CSV export.")
    $markdown.Add('')
}

$markdown.Add('> [!IMPORTANT]')
$markdown.Add('> This is a read-only item inventory and readiness aid, not an OAP enablement test. It does not change the workspace. It does not fully validate capacity, tenant settings, every workload-specific limitation, or every outbound connection.')
$markdown.Add('')
$markdown.Add('<a id="navigation"></a>')
$markdown.Add('## Navigation and quick filters')
$markdown.Add('')
$markdown.Add('- [Executive summary](#executive-summary)')
$markdown.Add("- [Confirmed blockers ($($blockers.Count))](#confirmed-blockers)")
$markdown.Add("- [Configuration attention ($($attention.Count))](#configuration-attention)")
$markdown.Add("- [Report semantic-model bindings ($($reportBindingItems.Count))](#report-model-bindings)")
$markdown.Add("- [Unknown item types ($($review.Count))](#unknown-item-types)")
$markdown.Add('- [Inventory by type](#inventory-by-type)')
$markdown.Add('- [All items](#all-items)')
$markdown.Add('- [OAP preflight and inventory checks](#inventory-checks)')
$markdown.Add('- [Recommended next steps](#recommended-next-steps)')
$markdown.Add('- [Assessment rules and references](#assessment-rules-and-references)')
$markdown.Add('')
$markdown.Add('Use your Markdown viewer search (<kbd>Ctrl</kbd> + <kbd>F</kbd> on Windows/Linux or <kbd>⌘</kbd> + <kbd>F</kbd> on macOS) to find an item name, type, or ID. The sections above act as static status filters; the companion HTML report provides live multi-field filtering.')
$markdown.Add('')

$markdown.Add('<a id="executive-summary"></a>')
$markdown.Add('## Executive summary')
$markdown.Add('')
$markdown.Add('| Result | Count | Meaning |')
$markdown.Add('|---|---:|---|')
$markdown.Add("| ⛔ Blocker | $($blockers.Count) | Unsupported item that prevents OAP enablement. |")
$markdown.Add("| 🟡 Attention | $($attention.Count) | Supported item that needs connection, binding, or workload-specific validation. |")
$markdown.Add("| ✅ Supported | $($supported.Count) | Item type is supported; normal connection validation still applies. |")
$markdown.Add("| ⚠️ Review | $($review.Count) | Unknown to this script; compare with current Microsoft documentation. |")
$markdown.Add('')
$markdown.Add("**Assessment:** $overallSummary")
$markdown.Add('')

function Add-MarkdownItemTable {
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]] $Output,

        [AllowEmptyCollection()]
        [Parameter(Mandatory)]
        [object[]] $Items,

        [string] $EmptyMessage = 'None.'
    )

    if ($Items.Count -eq 0) {
        $Output.Add($EmptyMessage)
        $Output.Add('')
        return
    }

    $Output.Add('| Status | Name | Type | Assessment | Binding | Item ID | Source |')
    $Output.Add('|---|---|---|---|---|---|---|')
    foreach ($item in $Items) {
        $statusIcon = switch ($item.Status) {
            'Blocker' { '⛔ Blocker' }
            'Attention' { '🟡 Attention' }
            'Supported' { '✅ Supported' }
            default { '⚠️ Review' }
        }

        $nameCell = ConvertTo-MarkdownCell $item.Name
        if (-not [string]::IsNullOrWhiteSpace($item.WebUrl)) {
            $nameCell = "[$nameCell]($($item.WebUrl))"
        }

        $Output.Add(
            "| $statusIcon " +
            "| $nameCell " +
            "| $(ConvertTo-MarkdownCell $item.Type) " +
            "| $(ConvertTo-MarkdownCell $item.Reason) " +
            "| $(ConvertTo-MarkdownCell $item.BindingStatus) " +
            "| $(ConvertTo-MarkdownCell $item.Id) " +
            "| $(ConvertTo-MarkdownCell $item.Source) |"
        )
    }
    $Output.Add('')
}

$markdown.Add('<a id="confirmed-blockers"></a>')
$markdown.Add('## Confirmed blockers')
$markdown.Add('')
$markdown.Add('These items are documented as unsupported in an OAP-protected workspace and must be removed or moved before OAP can be enabled.')
$markdown.Add('')
Add-MarkdownItemTable `
    -Output $markdown `
    -Items $blockers `
    -EmptyMessage 'No confirmed unsupported item-type blocker was found by the completed inventories.'
$markdown.Add('[Back to navigation](#navigation)')
$markdown.Add('')

$markdown.Add('<a id="configuration-attention"></a>')
$markdown.Add('## Configuration attention')
$markdown.Add('')
$markdown.Add('These items are not automatically blockers. Resolve or validate the stated condition before relying on OAP.')
$markdown.Add('')
Add-MarkdownItemTable `
    -Output $markdown `
    -Items $attention `
    -EmptyMessage 'No item-specific configuration warning was identified.'
$markdown.Add('[Back to navigation](#navigation)')
$markdown.Add('')

$markdown.Add('<a id="report-model-bindings"></a>')
$markdown.Add('## Interactive report semantic-model bindings')
$markdown.Add('')
$markdown.Add('Each interactive report is listed with its referenced semantic-model ID. Same-workspace bindings are verified. Cross-workspace or inaccessible models, missing model IDs, and unverified bindings need follow-up before relying on OAP. The inventory cannot distinguish an external model from one hidden by missing permissions.')
$markdown.Add('')
if ($reportBindingItems.Count -eq 0) {
    $markdown.Add('No interactive reports were returned by the completed inventories.')
    $markdown.Add('')
}
else {
    $markdown.Add('| Report | Semantic model ID | Binding check | Assessment |')
    $markdown.Add('|---|---|---|---|')
    foreach ($report in $reportBindingItems) {
        $reportName = ConvertTo-MarkdownCell $report.Name
        if (-not [string]::IsNullOrWhiteSpace($report.WebUrl)) {
            $reportName = "[$reportName]($($report.WebUrl))"
        }

        $markdown.Add(
            "| $reportName " +
            "| $(ConvertTo-MarkdownCell $report.DatasetId) " +
            "| $(ConvertTo-MarkdownCell $report.BindingStatus) " +
            "| $(ConvertTo-MarkdownCell $report.Reason) |"
        )
    }
    $markdown.Add('')
}
$markdown.Add('[Back to navigation](#navigation)')
$markdown.Add('')

$markdown.Add('<a id="unknown-item-types"></a>')
$markdown.Add('## Unknown item types')
$markdown.Add('')
$markdown.Add('These items are not declared blocked or supported by this script. Compare each type with the current OAP supported-item list.')
$markdown.Add('')
Add-MarkdownItemTable `
    -Output $markdown `
    -Items $review `
    -EmptyMessage 'No unrecognized item type was found.'
$markdown.Add('[Back to navigation](#navigation)')
$markdown.Add('')

$markdown.Add('<a id="inventory-by-type"></a>')
$markdown.Add('## Inventory by type')
$markdown.Add('')
$markdown.Add('| Type | Total | Blocker | Attention | Supported | Review |')
$markdown.Add('|---|---:|---:|---:|---:|---:|')
foreach ($typeGroup in ($orderedItems | Group-Object Type | Sort-Object Name)) {
    $groupItems = @($typeGroup.Group)
    $markdown.Add(
        "| $(ConvertTo-MarkdownCell $typeGroup.Name) " +
        "| $($groupItems.Count) " +
        "| $(@($groupItems | Where-Object Status -eq 'Blocker').Count) " +
        "| $(@($groupItems | Where-Object Status -eq 'Attention').Count) " +
        "| $(@($groupItems | Where-Object Status -eq 'Supported').Count) " +
        "| $(@($groupItems | Where-Object Status -eq 'Review').Count) |"
    )
}
if ($orderedItems.Count -eq 0) {
    $markdown.Add('| No items returned | 0 | 0 | 0 | 0 | 0 |')
}
$markdown.Add('')
$markdown.Add('[Back to navigation](#navigation)')
$markdown.Add('')

$markdown.Add('<a id="all-items"></a>')
$markdown.Add('## All items')
$markdown.Add('')
Add-MarkdownItemTable `
    -Output $markdown `
    -Items $orderedItems `
    -EmptyMessage 'No items were returned.'
$markdown.Add('[Back to navigation](#navigation)')
$markdown.Add('')

$markdown.Add('<a id="inventory-checks"></a>')
$markdown.Add('## OAP preflight and inventory checks')
$markdown.Add('')
$markdown.Add('| Check | Result | Required for readiness | Detail |')
$markdown.Add('|---|---|:---:|---|')
foreach ($check in $checks) {
    $checkIcon = switch ($check.Status) {
        'Passed' { '✅ Passed' }
        'Warning' { '⚠️ Warning' }
        default { '❌ Failed' }
    }
    $markdown.Add(
        "| $(ConvertTo-MarkdownCell $check.Check) " +
        "| $checkIcon " +
        "| $(if ($check.RequiredForReadiness) { 'Yes' } else { 'No' }) " +
        "| $(ConvertTo-MarkdownCell $check.Detail) |"
    )
}
$markdown.Add('')
$markdown.Add('[Back to navigation](#navigation)')
$markdown.Add('')

$markdown.Add('<a id="recommended-next-steps"></a>')
$markdown.Add('## Recommended next steps')
$markdown.Add('')
$markdown.Add('1. Move or remove every item in **Confirmed blockers**; do not delete anything until dependencies and retention requirements are understood.')
$markdown.Add('2. Resolve every required check marked Failed and manually confirm each required check marked Warning.')
$markdown.Add('3. Review every item under **Unknown item types** against the current supported-item documentation; unsupported artifacts prevent enabling OAP.')
$markdown.Add('4. For interactive reports, confirm the semantic model is in the same workspace. Cross-workspace bindings cannot query after OAP is enabled.')
$markdown.Add('5. For paginated reports, configure rules for data sources, semantic models, maps, and external images; convert AIXL semantic-model connections to XMLA.')
$markdown.Add('6. Confirm the tenant setting, Workspace Admin role, active non-trial Fabric F SKU, supported region, and Microsoft.Network registration in the capacity subscription.')
$markdown.Add('7. If Git synchronization must continue, turn on **Allow Git integration** in the workspace network settings after enabling OAP; Git is blocked by default.')
$markdown.Add('8. Configure required managed private endpoints or data connection rules for supported Fabric items, then test critical workloads.')
$markdown.Add('')
$markdown.Add('[Back to navigation](#navigation)')
$markdown.Add('')

$markdown.Add('<a id="assessment-rules-and-references"></a>')
$markdown.Add('## Assessment rules and references')
$markdown.Add('')
$markdown.Add('- **Blocker:** Power BI dashboard, scorecard, or metrics artifact.')
$markdown.Add('- **Matrix blocker:** any item type listed as unsupported for OAP in the Fabric security feature availability matrix.')
$markdown.Add('- **Attention:** supported item with a known binding, connection-rule, or workload-specific condition.')
$markdown.Add('- **Supported:** item type is listed as OAP-supported; connection validation may still be required.')
$markdown.Add('- **Review:** item type is unknown to this script and is not automatically labeled a blocker.')
$markdown.Add('')
$markdown.Add("- [Workspace OAP overview and supported item types]($script:OapOverviewUrl)")
$markdown.Add("- [OAP for interactive Power BI reports]($script:OapReportsUrl)")
$markdown.Add("- [OAP for paginated reports]($script:OapPaginatedReportsUrl)")
$markdown.Add("- [Enable workspace OAP]($script:OapSetupUrl)")
$markdown.Add("- [Fabric security feature availability by item type]($script:OapAvailabilityUrl)")
$markdown.Add('')
$markdown.Add('> Documentation and service support evolve. Re-run the script and compare Review items against the latest Microsoft documentation before making destructive changes.')
$markdown.Add('')
$markdown.Add('[Back to navigation](#navigation)')
$markdown.Add('')

$markdown | Set-Content -LiteralPath $MarkdownPath -Encoding utf8

# ----------------------------- HTML report -----------------------------
if (-not $SkipHtml) {
    $htmlItems = @(
        $orderedItems | ForEach-Object {
            [ordered]@{
                status        = $_.Status
                name          = $_.Name
                type          = $_.Type
                reason        = $_.Reason
                bindingStatus = $_.BindingStatus
                datasetId     = $_.DatasetId
                id            = $_.Id
                source        = $_.Source
                details       = $_.Details
                webUrl        = $_.WebUrl
            }
        }
    )

    $htmlChecks = @(
        $checks | ForEach-Object {
            [ordered]@{
                check                = $_.Check
                status               = $_.Status
                detail               = $_.Detail
                requiredForReadiness = $_.RequiredForReadiness
            }
        }
    )

    $dataObject = [ordered]@{
        workspaceName  = $workspaceName
        workspaceId    = [string] $WorkspaceId
        generatedUtc   = $generatedUtc
        overallStatus  = $overallStatus
        overallSummary = $overallSummary
        counts          = [ordered]@{
            total     = $orderedItems.Count
            blocker   = $blockers.Count
            attention = $attention.Count
            supported = $supported.Count
            review    = $review.Count
        }
        items           = $htmlItems
        checks          = $htmlChecks
        references      = [ordered]@{
            overview         = $script:OapOverviewUrl
            reports          = $script:OapReportsUrl
            paginatedReports = $script:OapPaginatedReportsUrl
            setup            = $script:OapSetupUrl
            availability     = $script:OapAvailabilityUrl
        }
    }

    $dataJson = $dataObject | ConvertTo-Json -Depth 12 -Compress
    $lineSeparator = [string] ([char] 0x2028)
    $paragraphSeparator = [string] ([char] 0x2029)
    $dataJson = $dataJson.Replace('&', '\u0026')
    $dataJson = $dataJson.Replace('<', '\u003c')
    $dataJson = $dataJson.Replace('>', '\u003e')
    $dataJson = $dataJson.Replace($lineSeparator, '\u2028')
    $dataJson = $dataJson.Replace($paragraphSeparator, '\u2029')

    $htmlTitle = ConvertTo-HtmlText "Fabric OAP readiness - $workspaceLabel"

    $htmlTemplate = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{color-scheme:light;--bg:#f5f7fb;--surface:#fff;--text:#172033;--muted:#5f6b7a;--line:#dfe3eb;--brand:#5b5fc7;--brand2:#464775;--blocker:#b42318;--blocker-bg:#fef3f2;--attention:#b54708;--attention-bg:#fffaeb;--supported:#027a48;--supported-bg:#ecfdf3;--review:#6941c6;--review-bg:#f4f3ff;--shadow:0 8px 24px rgba(16,24,40,.08)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Segoe UI,system-ui,-apple-system,BlinkMacSystemFont,sans-serif;line-height:1.45}a{color:#3b3fa3}.shell{max-width:1500px;margin:0 auto;padding:24px}.hero{background:linear-gradient(135deg,#24255d,#5b5fc7);color:white;border-radius:18px;padding:26px 28px;box-shadow:var(--shadow)}.hero h1{margin:0 0 8px;font-size:clamp(1.55rem,3vw,2.35rem)}.hero p{margin:.3rem 0;color:#eef0ff}.meta{display:flex;gap:10px 24px;flex-wrap:wrap;margin-top:14px;font-size:.92rem}.status-banner{margin:18px 0 0;padding:13px 15px;border-radius:10px;background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.24);font-weight:650}.cards{display:grid;grid-template-columns:repeat(5,minmax(150px,1fr));gap:14px;margin:18px 0}.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:16px;box-shadow:0 3px 12px rgba(16,24,40,.04);cursor:pointer;text-align:left;color:inherit}.card:hover,.card:focus{outline:2px solid var(--brand);outline-offset:1px}.card .label{font-size:.82rem;color:var(--muted);font-weight:650;text-transform:uppercase;letter-spacing:.04em}.card .value{font-size:1.8rem;font-weight:750;margin-top:5px}.card.blocker{border-top:4px solid var(--blocker)}.card.attention{border-top:4px solid var(--attention)}.card.supported{border-top:4px solid var(--supported)}.card.review{border-top:4px solid var(--review)}.panel{background:var(--surface);border:1px solid var(--line);border-radius:14px;margin:18px 0;box-shadow:0 3px 12px rgba(16,24,40,.04)}.panel-header{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:18px 20px;border-bottom:1px solid var(--line)}.panel-header h2{font-size:1.15rem;margin:0}.panel-body{padding:18px 20px}.controls{display:grid;grid-template-columns:minmax(260px,2fr) repeat(3,minmax(150px,1fr)) auto auto;gap:10px;align-items:end}.field label{display:block;color:var(--muted);font-size:.8rem;font-weight:650;margin:0 0 5px}.field input,.field select{width:100%;height:40px;border:1px solid #c8ced8;border-radius:8px;padding:7px 10px;background:white;color:var(--text)}.field input:focus,.field select:focus{outline:2px solid #a7a9ef;border-color:var(--brand)}button.action{height:40px;border:1px solid #c8ced8;border-radius:8px;background:white;color:var(--text);font-weight:650;padding:0 13px;cursor:pointer}button.action:hover{background:#f3f4f8}.table-wrap{overflow:auto;max-height:68vh;border-top:1px solid var(--line)}table{border-collapse:separate;border-spacing:0;width:100%;min-width:1050px}th,td{padding:11px 12px;border-bottom:1px solid #e8eaf0;text-align:left;vertical-align:top;font-size:.88rem}th{position:sticky;top:0;background:#f8f9fc;z-index:1;color:#344054;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;white-space:nowrap}th[data-sort]{cursor:pointer}th[data-sort]:hover{background:#eef0f6}tr:hover td{background:#fafbff}.name{font-weight:650}.id{font-family:Consolas,ui-monospace,monospace;font-size:.78rem;word-break:break-all}.badge{display:inline-flex;align-items:center;border-radius:999px;padding:3px 8px;font-size:.75rem;font-weight:700;white-space:nowrap}.badge.blocker{color:var(--blocker);background:var(--blocker-bg)}.badge.attention{color:var(--attention);background:var(--attention-bg)}.badge.supported{color:var(--supported);background:var(--supported-bg)}.badge.review{color:var(--review);background:var(--review-bg)}.muted{color:var(--muted)}.result-line{padding:12px 20px;color:var(--muted);font-size:.88rem;border-top:1px solid var(--line)}.empty{padding:34px;text-align:center;color:var(--muted)}.checks{display:grid;gap:10px}.check{border:1px solid var(--line);border-radius:10px;padding:12px 14px}.check-head{display:flex;gap:10px;align-items:center;justify-content:space-between}.check-title{font-weight:700}.check-detail{margin-top:5px;color:var(--muted);font-size:.88rem;word-break:break-word}.nav{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}.nav a{background:white;border:1px solid var(--line);border-radius:999px;padding:7px 11px;text-decoration:none;font-size:.85rem}.notice{border-left:4px solid var(--brand);padding:12px 14px;background:#f4f3ff;border-radius:0 8px 8px 0;color:#3c3d69}.footer{margin:24px 0;color:var(--muted);font-size:.84rem}.footer ul{padding-left:20px}.mobile-only{display:none}@media(max-width:1100px){.cards{grid-template-columns:repeat(3,1fr)}.controls{grid-template-columns:1fr 1fr 1fr}.controls .search{grid-column:1/-1}}@media(max-width:700px){.shell{padding:12px}.hero{padding:20px}.cards{grid-template-columns:1fr 1fr}.controls{grid-template-columns:1fr}.controls .search{grid-column:auto}.panel-header{align-items:flex-start;flex-direction:column}.mobile-only{display:inline}}@media print{body{background:white}.shell{max-width:none;padding:0}.hero{background:white;color:black;border:1px solid #aaa;box-shadow:none}.hero p{color:#333}.cards,.controls,.nav,.result-line,.footer{display:none}.panel{box-shadow:none;break-inside:avoid}.table-wrap{max-height:none;overflow:visible}th{position:static}table{min-width:0}th,td{font-size:8pt}.no-print{display:none}}
</style>
</head>
<body>
<div class="shell">
  <header class="hero" id="top">
    <h1>Fabric workspace OAP readiness</h1>
    <p id="workspaceLine"></p>
    <div class="meta"><span id="generatedLine"></span><span id="inventoryLine"></span></div>
    <div class="status-banner" id="statusBanner"></div>
  </header>

  <nav class="nav" aria-label="Report sections">
    <a href="#inventory">Search &amp; filter</a>
        <a href="#report-bindings">Report model bindings</a>
    <a href="#checks">Inventory checks</a>
    <a href="#guidance">Guidance</a>
    <a href="#references">References</a>
  </nav>

  <section class="cards" aria-label="Summary filters">
    <button class="card" data-card-status=""><span class="label">All items</span><div class="value" id="countTotal">0</div></button>
    <button class="card blocker" data-card-status="Blocker"><span class="label">Blockers</span><div class="value" id="countBlocker">0</div></button>
    <button class="card attention" data-card-status="Attention"><span class="label">Attention</span><div class="value" id="countAttention">0</div></button>
    <button class="card supported" data-card-status="Supported"><span class="label">Supported</span><div class="value" id="countSupported">0</div></button>
    <button class="card review" data-card-status="Review"><span class="label">Review</span><div class="value" id="countReview">0</div></button>
  </section>

  <section class="panel" id="inventory">
    <div class="panel-header"><h2>Workspace item inventory</h2><span class="muted">Select a summary card to filter by status</span></div>
    <div class="panel-body">
      <div class="controls">
        <div class="field search"><label for="search">Search name, type, reason, ID, source, or binding</label><input id="search" type="search" placeholder="Start typing to search…" autocomplete="off"></div>
        <div class="field"><label for="statusFilter">Status</label><select id="statusFilter"><option value="">All statuses</option></select></div>
        <div class="field"><label for="typeFilter">Item type</label><select id="typeFilter"><option value="">All item types</option></select></div>
        <div class="field"><label for="sourceFilter">Source</label><select id="sourceFilter"><option value="">All sources</option></select></div>
        <button class="action" id="clearFilters" type="button">Clear</button>
        <button class="action" id="exportCsv" type="button">Export visible CSV</button>
      </div>
    </div>
    <div class="table-wrap">
      <table id="itemTable">
        <thead><tr>
          <th data-sort="status">Status</th><th data-sort="name">Name</th><th data-sort="type">Type</th><th data-sort="reason">Assessment</th><th data-sort="bindingStatus">Binding</th><th data-sort="id">Item ID</th><th data-sort="source">Source</th>
        </tr></thead>
        <tbody id="itemRows"></tbody>
      </table>
      <div class="empty" id="emptyState" hidden>No items match the current filters.</div>
    </div>
    <div class="result-line" id="resultLine"></div>
  </section>

    <section class="panel" id="report-bindings">
        <div class="panel-header"><h2>Interactive report semantic-model bindings</h2><span class="muted" id="reportBindingSummary"></span></div>
        <div class="panel-body">
            <p class="muted">Same-workspace bindings are verified. Cross-workspace or inaccessible models, missing model IDs, and unverified bindings need follow-up before relying on OAP. The inventory cannot distinguish an external model from one hidden by missing permissions.</p>
        </div>
        <div class="table-wrap">
            <table id="reportBindingTable">
                <thead><tr><th>Report</th><th>Semantic model ID</th><th>Binding check</th><th>Assessment</th></tr></thead>
                <tbody id="reportBindingRows"></tbody>
            </table>
            <div class="empty" id="reportBindingEmpty" hidden>No interactive reports were returned by the completed inventories.</div>
        </div>
    </section>

  <section class="panel" id="checks">
    <div class="panel-header"><h2>OAP preflight and inventory checks</h2></div>
    <div class="panel-body"><div class="checks" id="checkList"></div></div>
  </section>

  <section class="panel" id="guidance">
    <div class="panel-header"><h2>Recommended next steps</h2></div>
    <div class="panel-body">
      <ol>
        <li>Move or remove every confirmed blocker only after checking dependencies and retention requirements.</li>
        <li>Resolve required checks marked Failed and manually confirm required checks marked Warning.</li>
        <li>Review unknown item types against current OAP support; unsupported artifacts prevent enabling OAP.</li>
        <li>Confirm each interactive report uses a semantic model in the same workspace.</li>
        <li>For paginated reports, configure rules for sources and external content, and convert AIXL model connections to XMLA.</li>
        <li>Confirm the tenant setting, Workspace Admin role, active non-trial Fabric F SKU, supported region, and Microsoft.Network registration for the capacity subscription.</li>
        <li>If Git sync must continue, enable Allow Git integration in workspace network settings; Git is blocked by default after OAP is enabled.</li>
        <li>Configure required managed private endpoints or data connection rules and test critical workloads.</li>
        <li>Validate the Fabric F SKU, tenant setting, Workspace Admin role, regional availability, and propagation time separately.</li>
      </ol>
      <div class="notice"><strong>Read-only assessment.</strong> This report does not enable OAP or modify any workspace item.</div>
    </div>
  </section>

  <section class="panel" id="references">
    <div class="panel-header"><h2>Assessment rules and references</h2></div>
    <div class="panel-body">
      <ul>
        <li><strong>Blocker:</strong> unsupported dashboard, scorecard, or metrics artifact.</li>
        <li><strong>Attention:</strong> supported item with a known binding, connection-rule, or workload-specific condition.</li>
        <li><strong>Supported:</strong> listed item type; connection validation may still be required.</li>
        <li><strong>Review:</strong> item type unknown to this script; it is not automatically called a blocker.</li>
      </ul>
      <ul id="referenceLinks"></ul>
    </div>
  </section>

  <footer class="footer"><a href="#top">Back to top</a> · Self-contained report generated by Test-FabricOapReadiness.ps1. Documentation and service support evolve; verify before destructive changes.</footer>
</div>
<script>
'use strict';
const report = __REPORT_DATA__;
const state = { sortKey: 'status', sortDirection: 1, visible: [] };
const statusOrder = { Blocker: 1, Attention: 2, Supported: 3, Review: 4 };
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const badge = status => `<span class="badge ${esc(status.toLowerCase())}">${status === 'Blocker' ? '⛔' : status === 'Attention' ? '🟡' : status === 'Supported' ? '✅' : '⚠️'} ${esc(status)}</span>`;

function unique(values){ return [...new Set(values.filter(Boolean))].sort((a,b)=>a.localeCompare(b,undefined,{sensitivity:'base'})); }
function addOptions(select, values){ values.forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v;select.appendChild(o);}); }
function searchText(item){ return [item.status,item.name,item.type,item.reason,item.bindingStatus,item.id,item.source,item.details].join(' ').toLowerCase(); }
function compare(a,b,key){
  if(key==='status') return (statusOrder[a.status]??99)-(statusOrder[b.status]??99) || a.name.localeCompare(b.name);
  return String(a[key]??'').localeCompare(String(b[key]??''),undefined,{numeric:true,sensitivity:'base'});
}
function itemName(item){const label=esc(item.name||'(unnamed item)');return item.webUrl?`<a class="name" href="${esc(item.webUrl)}" target="_blank" rel="noopener noreferrer">${label}</a>`:`<span class="name">${label}</span>`;}
function applyFilters(){
  const q=$('search').value.trim().toLowerCase();
  const status=$('statusFilter').value, type=$('typeFilter').value, source=$('sourceFilter').value;
  state.visible=report.items.filter(i=>(!q||searchText(i).includes(q))&&(!status||i.status===status)&&(!type||i.type===type)&&(!source||i.source.includes(source)));
  state.visible.sort((a,b)=>state.sortDirection*compare(a,b,state.sortKey));
  renderRows();
}
function renderRows(){
  $('itemRows').innerHTML=state.visible.map(i=>`<tr><td>${badge(i.status)}</td><td>${itemName(i)}</td><td>${esc(i.type||'-')}</td><td>${esc(i.reason||'-')}</td><td>${esc(i.bindingStatus||'-')}</td><td class="id">${esc(i.id||'-')}</td><td>${esc(i.source||'-')}</td></tr>`).join('');
  $('emptyState').hidden=state.visible.length>0;
  $('itemTable').hidden=state.visible.length===0;
  $('resultLine').textContent=`Showing ${state.visible.length} of ${report.items.length} items · sorted by ${state.sortKey} ${state.sortDirection===1?'ascending':'descending'}`;
}
function setStatusFilter(status){$('statusFilter').value=status;applyFilters();$('inventory').scrollIntoView({behavior:'smooth',block:'start'});}
function csvCell(value){const s=String(value??'');return /[",\r\n]/.test(s)?`"${s.replace(/"/g,'""')}"`:s;}
function exportCsv(){
  const columns=[['Status','status'],['Name','name'],['Type','type'],['Assessment','reason'],['Binding','bindingStatus'],['Item ID','id'],['Source','source'],['Web URL','webUrl']];
  const lines=[columns.map(c=>csvCell(c[0])).join(','),...state.visible.map(i=>columns.map(c=>csvCell(i[c[1]])).join(','))];
  const blob=new Blob(['\uFEFF'+lines.join('\r\n')],{type:'text/csv;charset=utf-8'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`Fabric-OAP-visible-${report.workspaceId}.csv`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);
}
function renderReportBindings(){
    const reports=report.items.filter(i=>i.type==='Report');
    const needsReview=reports.filter(i=>i.bindingStatus!=='Same workspace').length;
    $('reportBindingSummary').textContent=`${reports.length} report(s) · ${needsReview} need binding review`;
    $('reportBindingTable').hidden=reports.length===0;
    $('reportBindingEmpty').hidden=reports.length>0;
    $('reportBindingRows').innerHTML=reports.map(i=>`<tr><td>${itemName(i)}</td><td class="id">${esc(i.datasetId||'-')}</td><td>${esc(i.bindingStatus||'-')}</td><td>${badge(i.status)} ${esc(i.reason||'-')}</td></tr>`).join('');
}
function renderChecks(){
  $('checkList').innerHTML=report.checks.map(c=>`<div class="check"><div class="check-head"><span class="check-title">${esc(c.check)}</span><span>${c.status==='Passed'?'✅':c.status==='Warning'?'⚠️':'❌'} ${esc(c.status)}${c.requiredForReadiness?' · required':''}</span></div><div class="check-detail">${esc(c.detail)}</div></div>`).join('');
}
function init(){
  const ws=report.workspaceName?`${report.workspaceName} (${report.workspaceId})`:report.workspaceId;
  $('workspaceLine').textContent=`Workspace: ${ws}`;$('generatedLine').textContent=`Generated: ${report.generatedUtc}`;$('inventoryLine').textContent=`Items inventoried: ${report.counts.total}`;
  $('statusBanner').textContent=`${report.overallStatus} — ${report.overallSummary}`;
  $('countTotal').textContent=report.counts.total;$('countBlocker').textContent=report.counts.blocker;$('countAttention').textContent=report.counts.attention;$('countSupported').textContent=report.counts.supported;$('countReview').textContent=report.counts.review;
  addOptions($('statusFilter'),unique(report.items.map(i=>i.status)));addOptions($('typeFilter'),unique(report.items.map(i=>i.type)));addOptions($('sourceFilter'),unique(report.items.flatMap(i=>i.source.split(';').map(s=>s.trim()))));
  document.querySelectorAll('[data-card-status]').forEach(b=>b.addEventListener('click',()=>setStatusFilter(b.dataset.cardStatus)));
  ['search','statusFilter','typeFilter','sourceFilter'].forEach(id=>$(id).addEventListener(id==='search'?'input':'change',applyFilters));
  $('clearFilters').addEventListener('click',()=>{$('search').value='';$('statusFilter').value='';$('typeFilter').value='';$('sourceFilter').value='';applyFilters();});$('exportCsv').addEventListener('click',exportCsv);
  document.querySelectorAll('th[data-sort]').forEach(th=>th.addEventListener('click',()=>{const key=th.dataset.sort;if(state.sortKey===key)state.sortDirection*=-1;else{state.sortKey=key;state.sortDirection=1;}applyFilters();}));
    const refs=[['Workspace OAP overview and supported item types',report.references.overview],['OAP for interactive Power BI reports',report.references.reports],['OAP for paginated reports',report.references.paginatedReports],['Enable workspace OAP',report.references.setup],['Fabric security feature availability by item type',report.references.availability]];
  $('referenceLinks').innerHTML=refs.map(r=>`<li><a href="${esc(r[1])}" target="_blank" rel="noopener noreferrer">${esc(r[0])}</a></li>`).join('');
    renderReportBindings();renderChecks();applyFilters();
}
init();
</script>
</body>
</html>
'@

    $html = $htmlTemplate.Replace('__TITLE__', $htmlTitle)
    $html = $html.Replace('__REPORT_DATA__', $dataJson)

    $html | Set-Content -LiteralPath $HtmlPath -Encoding utf8
}

Write-Host ''
Write-Host "Markdown report: $MarkdownPath" -ForegroundColor Green
if (-not $SkipHtml) {
    Write-Host "Interactive HTML report: $HtmlPath" -ForegroundColor Green
}
Write-Host "Result: $overallStatus"
Write-Host "Items: $($orderedItems.Count) | Blockers: $($blockers.Count) | Attention: $($attention.Count) | Review: $($review.Count)"

if ($blockers.Count -gt 0) {
    exit 1
}

if ($review.Count -gt 0 -or $requiredChecksNeedingConfirmation.Count -gt 0) {
    exit 2
}

exit 0
