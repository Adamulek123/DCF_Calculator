param(
    [Parameter(Mandatory = $true)]
    [string]$SecretsPath,
    [string]$BackendOrigin = "http://localhost:5000",
    [string[]]$AllowedRemoteOrigin = @()
)

$ErrorActionPreference = "Stop"

try {
    $backendUri = [System.Uri]::new($BackendOrigin, [System.UriKind]::Absolute)
    if ($backendUri.Scheme -notin @("http", "https")) {
        throw "BackendOrigin must use HTTP or HTTPS."
    }
    if ($backendUri.AbsolutePath -ne "/" -or $backendUri.Query -or $backendUri.Fragment -or $backendUri.UserInfo) {
        throw "BackendOrigin must be an origin only (for example, https://api.example.com)."
    }
    $normalizedOrigin = $backendUri.GetLeftPart([System.UriPartial]::Authority).TrimEnd("/")
    if (-not $backendUri.IsLoopback) {
        if ($backendUri.Scheme -ne "https") {
            throw "Non-loopback BackendOrigin values must use HTTPS."
        }
        $normalizedAllowlist = @($AllowedRemoteOrigin | ForEach-Object {
            ([System.Uri]::new($_, [System.UriKind]::Absolute)).GetLeftPart([System.UriPartial]::Authority).TrimEnd("/")
        })
        if ($normalizedOrigin -notin $normalizedAllowlist) {
            throw "Refusing to send the refresh secret to an unapproved remote origin. Pass the exact origin with -AllowedRemoteOrigin."
        }
    }

    $config = Get-Content -LiteralPath $SecretsPath -Raw | ConvertFrom-Json
    if (-not $config.EARNINGS_REFRESH_SECRET) {
        throw "EARNINGS_REFRESH_SECRET is missing from the local secrets file."
    }

    $headers = @{ Authorization = "Bearer $($config.EARNINGS_REFRESH_SECRET)" }
    $result = Invoke-RestMethod `
        -Method Post `
        -Uri "$normalizedOrigin/internal/earnings-calendar/refresh" `
        -Headers $headers `
        -MaximumRedirection 0 `
        -TimeoutSec 120

    $manifest = Invoke-RestMethod `
        -Method Get `
        -Uri "$normalizedOrigin/earnings-calendar/manifest" `
        -MaximumRedirection 0 `
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
