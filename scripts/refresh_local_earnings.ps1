param(
    [Parameter(Mandatory = $true)]
    [string]$SecretsPath,
    [string]$BackendOrigin = "http://localhost:5000"
)

$ErrorActionPreference = "Stop"

try {
    $config = Get-Content -LiteralPath $SecretsPath -Raw | ConvertFrom-Json
    if (-not $config.EARNINGS_REFRESH_SECRET) {
        throw "EARNINGS_REFRESH_SECRET is missing from the local secrets file."
    }

    $headers = @{ Authorization = "Bearer $($config.EARNINGS_REFRESH_SECRET)" }
    $result = Invoke-RestMethod `
        -Method Post `
        -Uri "$BackendOrigin/internal/earnings-calendar/refresh" `
        -Headers $headers `
        -TimeoutSec 120

    $manifest = Invoke-RestMethod `
        -Method Get `
        -Uri "$BackendOrigin/earnings-calendar/manifest" `
        -TimeoutSec 15

    $eventCount = ($manifest.weeks.PSObject.Properties.Value |
        Measure-Object -Property eventCount -Sum).Sum
    if (-not $eventCount -or $eventCount -lt 1) {
        throw "The refresh returned without publishing any calendar events."
    }

    Write-Host "Earnings calendar status: $($result.status) ($eventCount events cached)"
    exit 0
} catch {
    $detail = $_.ErrorDetails.Message
    if (-not $detail) {
        $detail = $_.Exception.Message
    }
    Write-Host "ERROR: Earnings calendar refresh failed: $detail"
    exit 1
}
