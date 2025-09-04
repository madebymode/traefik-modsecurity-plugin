#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Runs integration tests for the Traefik ModSecurity Plugin

.DESCRIPTION
    This script starts the Docker Compose services, waits for them to be ready,
    runs the Pester integration tests, and then cleans up the services.

.PARAMETER SkipDockerCleanup
    Skip stopping Docker services after tests complete (useful for debugging)

.PARAMETER SkipWait
    Skip waiting for services to be ready (assumes they're already running)

.PARAMETER TestPath
    Path to the Pester test file (defaults to ./scripts/integration-tests.Tests.ps1)

.PARAMETER ComposeFile
    Path to the Docker Compose file (defaults to ./docker-compose.test.yml)

.EXAMPLE
    ./Test-Integration.ps1
    Runs the full integration test suite

.EXAMPLE
    ./Test-Integration.ps1 -SkipDockerCleanup
    Runs tests but leaves Docker services running for debugging

.EXAMPLE
    ./Test-Integration.ps1 -SkipWait
    Runs tests assuming services are already running
#>

[CmdletBinding()]
param(
    [switch]$SkipDockerCleanup,
    [switch]$SkipWait,
    [string]$TestPath = "./scripts/integration-tests.Tests.ps1",
    [string]$ComposeFile = "./docker-compose.test.yml"
)

$ErrorActionPreference = "Stop"

# Colors for output
$Colors = @{
    Info = "Cyan"
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
    Gray = "Gray"
}

function Write-Step {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "🔄 $Message" -ForegroundColor $Color
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor $Colors.Success
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor $Colors.Warning
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor $Colors.Error
}

function Test-ServiceHealth {
    param(
        [string]$Url,
        [string]$ServiceName,
        [int]$TimeoutSeconds = 30,
        [int]$RetryIntervalSeconds = 3
    )
    
    Write-Step "Waiting for $ServiceName to be ready..."
    $elapsed = 0
    
    do {
        try {
            $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 5 -UseBasicParsing
            if ($response.StatusCode -eq 200) {
                Write-Success "$ServiceName is ready!"
                return $true
            }
        }
        catch {
            # Service not ready yet, continue waiting
        }
        
        Start-Sleep $RetryIntervalSeconds
        $elapsed += $RetryIntervalSeconds
        
        if ($elapsed % 15 -eq 0) {
            Write-Host "  Still waiting for $ServiceName... ($elapsed/$TimeoutSeconds seconds)" -ForegroundColor $Colors.Gray
        }
        
    } while ($elapsed -lt $TimeoutSeconds)
    
    Write-Error "$ServiceName failed to become ready within $TimeoutSeconds seconds"
    return $false
}

function Test-DockerCompose {
    Write-Step "Checking Docker Compose availability..."
    try {
        $dockerComposeVersion = docker compose version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Docker Compose is available: $($dockerComposeVersion -split "`n" | Select-Object -First 1)"
        } else {
            throw "Docker Compose not found"
        }
    }
    catch {
        Write-Error "Docker Compose is not available. Please install Docker Desktop or Docker Compose."
        return $false
    }
    return $true
}

function Start-TestServices {
    param([string]$ComposeFile)
    
    Write-Step "Starting Docker Compose services using $ComposeFile..."
    try {
        # Stop any existing containers first
        docker compose -f $ComposeFile down -v --remove-orphans 2>$null | Out-Null
        
        # Start fresh containers
        $output = docker compose -f $ComposeFile up -d 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Docker Compose Output:" -ForegroundColor $Colors.Gray
            Write-Host $output -ForegroundColor $Colors.Gray
            throw "Failed to start Docker services (exit code: $LASTEXITCODE)"
        }
        Write-Success "Docker services started successfully"
        
        # Show running containers for verification
        Write-Host "`nRunning containers:" -ForegroundColor $Colors.Info
        docker compose -f $ComposeFile ps
        
    }
    catch {
        Write-Error "Failed to start Docker services: $($_.Exception.Message)"
        throw
    }
}

function Wait-ForAllServices {
    Write-Step "Waiting for all services to become ready..."
    
    $services = @(
        @{ Url = "http://localhost:8080/api/rawdata"; Name = "Traefik API" },
        @{ Url = "http://localhost:8000/bypass"; Name = "Whoami Bypass service" },
        @{ Url = "http://localhost:8000/protected"; Name = "Whoami Protected service" }
    )
    
    $servicesReady = @()
    foreach ($service in $services) {
        $servicesReady += (Test-ServiceHealth -Url $service.Url -ServiceName $service.Name -TimeoutSeconds 30)
    }
    
    if ($servicesReady -contains $false) {
        Write-Error "One or more services failed to start properly"
        Write-Host "`nContainer logs for debugging:" -ForegroundColor $Colors.Warning
        docker compose -f $ComposeFile logs --tail=20
        return $false
    }
    
    Write-Success "All services are ready for testing!"
    return $true
}

# Main execution
$exitCode = 0
try {
    Write-Host ""
    Write-Host "🚀 Traefik ModSecurity Plugin Integration Test Runner" -ForegroundColor $Colors.Info
    Write-Host "=====================================================" -ForegroundColor $Colors.Info
    Write-Host ""

    # Verify files exist
    if (-not (Test-Path $ComposeFile)) {
        Write-Error "Docker Compose file not found: $ComposeFile"
        exit 1
    }
    
    if (-not (Test-Path $TestPath)) {
        Write-Error "Test file not found: $TestPath"
        exit 1
    }

    # Check if Pester is available
    Write-Step "Checking Pester availability..."
    try {
        Import-Module Pester -Force -ErrorAction Stop
        $pesterVersion = (Get-Module Pester).Version
        Write-Success "Pester $pesterVersion is available"
    }
    catch {
        Write-Warning "Pester module not found. Installing Pester..."
        try {
            Install-Module -Name Pester -Force -Scope CurrentUser -SkipPublisherCheck -AllowClobber
            Import-Module Pester -Force
            Write-Success "Pester installed and imported successfully"
        }
        catch {
            Write-Error "Failed to install Pester: $($_.Exception.Message)"
            exit 1
        }
    }

    # Check Docker Compose
    if (-not (Test-DockerCompose)) {
        exit 1
    }

    # Start Docker services
    Start-TestServices -ComposeFile $ComposeFile

    if (-not $SkipWait) {
        # Wait for services to be ready
        if (-not (Wait-ForAllServices)) {
            exit 1
        }
    } else {
        Write-Warning "Skipping service readiness check (assuming services are already running)"
    }

    # Run Pester tests
    Write-Step "Running Pester integration tests..."
    Write-Host ""
    
    try {
        $pesterConfig = New-PesterConfiguration
        $pesterConfig.Run.Path = $TestPath
        $pesterConfig.Output.Verbosity = 'Detailed'
        $pesterConfig.Run.Exit = $false
        $pesterConfig.Run.PassThru = $true
        
        # Run tests with timeout protection
        $result = Invoke-Pester -Configuration $pesterConfig
        
        Write-Host ""
        if ($result -and $result.FailedCount -eq 0) {
            Write-Success "All integration tests passed! 🎉"
            Write-Host "📊 Test Summary: $($result.PassedCount) passed, $($result.FailedCount) failed, $($result.SkippedCount) skipped" -ForegroundColor $Colors.Info
            $exitCode = 0
        } elseif ($result) {
            Write-Error "$($result.FailedCount) test(s) failed out of $($result.TotalCount) total tests"
            Write-Host "📊 Test Summary: $($result.PassedCount) passed, $($result.FailedCount) failed, $($result.SkippedCount) skipped" -ForegroundColor $Colors.Warning
            $exitCode = 1
        } else {
            Write-Warning "Could not determine test results"
            $exitCode = 1
        }
    }
    catch {
        Write-Error "Failed to run Pester tests: $($_.Exception.Message)"
        $exitCode = 1
    }
}
catch {
    Write-Error "Unexpected error: $($_.Exception.Message)"
    $exitCode = 1
}
finally {
    # Cleanup Docker services
    if (-not $SkipDockerCleanup) {
        Write-Step "Cleaning up Docker services..."
        try {
            docker compose -f $ComposeFile down -v --remove-orphans 2>$null
            Write-Success "Docker services stopped and cleaned up"
        }
        catch {
            Write-Warning "Failed to clean up Docker services: $($_.Exception.Message)"
        }
    } else {
        Write-Warning "Skipping Docker cleanup (services left running for debugging)"
        Write-Host "To manually stop services, run: docker compose -f $ComposeFile down -v" -ForegroundColor $Colors.Gray
        Write-Host "To view logs, run: docker compose -f $ComposeFile logs" -ForegroundColor $Colors.Gray
    }
    
    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor $Colors.Info
    if ($exitCode -eq 0) {
        Write-Host "🏁 Integration tests completed successfully!" -ForegroundColor $Colors.Success
    } else {
        Write-Host "🏁 Integration tests completed with failures!" -ForegroundColor $Colors.Error
    }
    Write-Host ""
}

exit $exitCode
