# PowerShell Test Helper Functions for Traefik ModSecurity Plugin
# These functions can be reused across multiple test files

# Test configuration constants
$script:DefaultTimeout = 15
$script:DefaultRetryInterval = 2

<#
.SYNOPSIS
    Makes HTTP requests with comprehensive error handling

.DESCRIPTION
    A robust wrapper around Invoke-WebRequest with consistent error handling,
    timeout management, and optional security bypass for testing scenarios

.PARAMETER Uri
    The URL to make the request to

.PARAMETER Method
    HTTP method (GET, POST, etc.)

.PARAMETER Headers
    Hash table of headers to include

.PARAMETER Body
    Request body content

.PARAMETER TimeoutSec
    Request timeout in seconds

.PARAMETER AllowInsecure
    Skip certificate validation for HTTPS
#>
function Invoke-SafeWebRequest {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [int]$TimeoutSec = 10,
        [switch]$AllowInsecure
    )
    
    try {
        $params = @{
            Uri = $Uri
            Method = $Method
            Headers = $Headers
            TimeoutSec = $TimeoutSec
            UseBasicParsing = $true
        }
        
        if ($Body) {
            $params.Body = $Body
        }
        
        if ($AllowInsecure) {
            $params.SkipCertificateCheck = $true
        }
        
        return Invoke-WebRequest @params
    }
    catch {
        Write-Host "Request failed: $($_.Exception.Message)" -ForegroundColor Yellow
        throw
    }
}

<#
.SYNOPSIS
    Waits for a service to become ready by checking its health endpoint

.DESCRIPTION
    Polls a service endpoint until it returns a successful response or timeout is reached.
    Uses exponential backoff for efficient waiting.

.PARAMETER Url
    The health check URL for the service

.PARAMETER ServiceName
    Human-readable name for logging

.PARAMETER TimeoutSeconds
    Maximum time to wait before giving up

.PARAMETER RetryInterval
    Time between retry attempts in seconds
#>
function Wait-ForService {
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [Parameter(Mandatory)]
        [string]$ServiceName,
        [int]$TimeoutSeconds = 30,
        [int]$RetryInterval = 2
    )
    
    Write-Host "Waiting for $ServiceName to be ready..." -ForegroundColor Cyan
    $elapsed = 0
    
    do {
        try {
            $response = Invoke-SafeWebRequest -Uri $Url -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
                Write-Host "✅ $ServiceName is ready!" -ForegroundColor Green
                return $true
            }
        }
        catch {
            # Service not ready yet, continue waiting
        }
        
        Start-Sleep $RetryInterval
        $elapsed += $RetryInterval
        
        if ($elapsed % 10 -eq 0) {
            Write-Host "  Still waiting for $ServiceName... ($elapsed/$TimeoutSeconds seconds)" -ForegroundColor Gray
        }
        
    } while ($elapsed -lt $TimeoutSeconds)
    
    Write-Host "❌ $ServiceName failed to become ready within $TimeoutSeconds seconds" -ForegroundColor Red
    return $false
}

<#
.SYNOPSIS
    Tests multiple services for readiness

.PARAMETER Services
    Array of service objects with Url and Name properties

.PARAMETER TimeoutSeconds
    Per-service timeout in seconds
#>
function Wait-ForAllServices {
    param(
        [Parameter(Mandatory)]
        [array]$Services,
        [int]$TimeoutSeconds = 30
    )
    
    Write-Host "`n🔄 Waiting for all services to be ready..." -ForegroundColor Cyan
    
    $servicesReady = @()
    foreach ($service in $Services) {
        $servicesReady += (Wait-ForService -Url $service.Url -ServiceName $service.Name -TimeoutSeconds $TimeoutSeconds)
    }
    
    if ($servicesReady -contains $false) {
        throw "One or more services failed to start properly"
    }
    
    Write-Host "✅ All services are ready for testing!`n" -ForegroundColor Green
    return $true
}

<#
.SYNOPSIS
    Tests if a request is blocked by WAF

.DESCRIPTION
    Attempts a potentially malicious request and verifies it gets blocked
    with an appropriate HTTP error status

.PARAMETER Url
    The URL to test (should include malicious payload)

.PARAMETER ExpectedMinStatus
    Minimum expected HTTP status code for blocked requests (default: 400)
#>
function Test-WafBlocking {
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [int]$ExpectedMinStatus = 400
    )
    
    try {
        $response = Invoke-SafeWebRequest -Uri $Url
        # If we get here, the request wasn't blocked
        throw "Expected request to be blocked but got status: $($response.StatusCode)"
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        # Expected - request was blocked
        $response = $_.Exception.Response
        if ($response) {
            $statusCode = [int]$response.StatusCode
            $statusCode | Should -BeGreaterOrEqual $ExpectedMinStatus
            Write-Host "✅ WAF blocked request with status: $statusCode" -ForegroundColor Green
            return $statusCode
        }
    }
}

<#
.SYNOPSIS
    Tests multiple malicious patterns to ensure they're blocked

.PARAMETER BaseUrl
    Base URL for the protected endpoint

.PARAMETER Patterns
    Array of malicious query string patterns to test
#>
function Test-MaliciousPatterns {
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,
        [Parameter(Mandatory)]
        [array]$Patterns
    )
    
    foreach ($pattern in $Patterns) {
        $testUrl = "$BaseUrl$pattern"
        Test-WafBlocking -Url $testUrl
        Write-Host "✅ Pattern blocked: $pattern" -ForegroundColor Green
    }
}

<#
.SYNOPSIS
    Tests multiple patterns to ensure they're allowed through

.PARAMETER BaseUrl
    Base URL for the bypass endpoint

.PARAMETER Patterns
    Array of query string patterns that should be allowed
#>
function Test-BypassPatterns {
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,
        [Parameter(Mandatory)]
        [array]$Patterns
    )
    
    foreach ($pattern in $Patterns) {
        $bypassUrl = "$BaseUrl$pattern"
        $response = Invoke-SafeWebRequest -Uri $bypassUrl
        $response.StatusCode | Should -Be 200
        Write-Host "✅ Bypass allowed: $pattern" -ForegroundColor Green
    }
}

<#
.SYNOPSIS
    Measures response time for a given endpoint

.PARAMETER Url
    URL to test response time for

.PARAMETER MaxResponseTimeMs
    Maximum acceptable response time in milliseconds
#>
function Test-ResponseTime {
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [int]$MaxResponseTimeMs = 5000
    )
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $response = Invoke-SafeWebRequest -Uri $Url
    $stopwatch.Stop()
    
    $response.StatusCode | Should -Be 200
    $stopwatch.ElapsedMilliseconds | Should -BeLessThan $MaxResponseTimeMs
    
    Write-Host "Response time: $($stopwatch.ElapsedMilliseconds)ms" -ForegroundColor Cyan
    return $stopwatch.ElapsedMilliseconds
}

<#
.SYNOPSIS
    Tests concurrent request handling

.PARAMETER Url
    URL to test with concurrent requests

.PARAMETER RequestCount
    Number of concurrent requests to make

.PARAMETER MinSuccessCount
    Minimum number of requests that should succeed
#>
function Test-ConcurrentRequests {
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [int]$RequestCount = 5,
        [int]$MinSuccessCount = 3
    )
    
    $jobs = @()
    1..$RequestCount | ForEach-Object {
        $jobs += Start-Job -ScriptBlock {
            param($TestUrl)
            try {
                $response = Invoke-WebRequest -Uri $TestUrl -UseBasicParsing -TimeoutSec 10
                return @{ StatusCode = $response.StatusCode; Success = $true }
            }
            catch {
                return @{ StatusCode = 0; Success = $false; Error = $_.Exception.Message }
            }
        } -ArgumentList $Url
    }
    
    $results = $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job
    
    $successfulRequests = ($results | Where-Object { $_.Success }).Count
    $successfulRequests | Should -BeGreaterOrEqual $MinSuccessCount
    
    Write-Host "Successful concurrent requests: $successfulRequests/$RequestCount" -ForegroundColor Cyan
    return $successfulRequests
}

# Helper functions are available when dot-sourced
# No Export-ModuleMember needed for dot-sourcing
