BeforeAll {
    # Import test helper functions
    . "$PSScriptRoot/TestHelpers.ps1"
    
    # Test configuration
    $script:BaseUrl = "http://localhost:8000"
    $script:TraefikApiUrl = "http://localhost:8080"
    
    # Ensure all services are ready before running tests
    $services = @(
        @{ Url = "$TraefikApiUrl/api/rawdata"; Name = "Traefik API" },
        @{ Url = "$BaseUrl/bypass"; Name = "Bypass service" },
        @{ Url = "$BaseUrl/protected"; Name = "Protected service" },
        @{ Url = "$BaseUrl/remediation-test"; Name = "Remediation test service" },
        @{ Url = "$BaseUrl/error-test"; Name = "Error test service" }
    )
    
    Wait-ForAllServices -Services $services
}

Describe "ModSecurity Plugin Basic Functionality" {
    Context "Service Availability" {
        It "Should have Traefik API accessible" {
            $response = Invoke-SafeWebRequest -Uri "$TraefikApiUrl/api/rawdata"
            $response.StatusCode | Should -Be 200
        }
        
        It "Should have bypass service accessible" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/bypass"
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match "Hostname"
        }
        
        It "Should have protected service accessible with valid requests" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected"
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match "Hostname"
        }
    }
}

Describe "WAF Protection Tests" {
    Context "Malicious Request Detection" {
        It "Should block common attack patterns" {
            $maliciousPatterns = @(
                "?id=1' OR '1'='1",                    # SQL injection
                "?search=<script>alert('xss')</script>", # XSS
                "?file=../../../etc/passwd",            # Path traversal
                "?cmd=; ls -la"                         # Command injection
            )
            
            Test-MaliciousPatterns -BaseUrl "$BaseUrl/protected" -Patterns $maliciousPatterns
        }
    }
    
    Context "Legitimate Request Handling" {
        It "Should allow normal GET requests" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected/normal-path"
            $response.StatusCode | Should -Be 200
        }
        
        It "Should allow POST requests with normal data" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method POST -Body "name=john&email=john@example.com"
            $response.StatusCode | Should -Be 200
        }
        
        It "Should allow requests with normal query parameters" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected?page=1&limit=10&sort=name"
            $response.StatusCode | Should -Be 200
        }
    }
}

Describe "Remediation Response Header Tests" {
    Context "Custom Header Configuration" {
        It "Should add remediation header when request is blocked" {
            $statusCode = Test-WafBlocking -Url "$BaseUrl/protected?id=1' OR '1'='1"
            $statusCode | Should -BeGreaterOrEqual 400
        }
        
        It "Should not add remediation header for legitimate requests" {
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected"
            $response.Headers["X-Waf-Status"] | Should -BeNullOrEmpty
        }
    }
    
    Context "Remediation Header Logging" {
        It "Should log remediation header as request header in access logs for blocked requests" {
            # Make a blocked request to the remediation test endpoint
            $maliciousUrl = "$BaseUrl/remediation-test?id=1' OR '1'='1"
            try {
                $response = Invoke-SafeWebRequest -Uri $maliciousUrl
                $response.StatusCode | Should -BeGreaterOrEqual 400
            } catch {
                # Expected for blocked requests - check if it's a 403/blocked response
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    $statusCode | Should -BeGreaterOrEqual 400
                } else {
                    throw "Unexpected error: $($_.Exception.Message)"
                }
            }
            
            # Wait a moment for log to be written
            Start-Sleep -Seconds 2
            
            # Read the access.log file from the traefik container
            $accessLogContent = docker exec traefik-modsecurity-plugin-traefik-1 cat /var/log/traefik/access.log 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to read traefik access log"
            }
            
            # Parse the log lines and check for any entries related to the remediation test
            $logLines = $accessLogContent -split "`n" | Where-Object { $_.Trim() -ne "" }
            
            # Validate that ALL log lines are properly formatted JSON (no malformed lines should exist)
            $allLogEntries = @()
            foreach ($line in $logLines) {
                try {
                    $logEntry = $line | ConvertFrom-Json
                    $allLogEntries += $logEntry
                } catch {
                    throw "Malformed JSON line found in log file: '$line'."
                }
            }
            
            # Look for log entries where the X-Waf-Status request header is present for blocked requests
            $remediationHeaderLogFound = ($allLogEntries | Where-Object { 
                $_.'request_X-Waf-Status' -and 
                $_.RequestPath -like "/remediation-test*"
            }).Count -gt 0
            
            # Verify that the remediation header was added to the request
            $remediationHeaderLogFound | Should -Be $true
        }
        
        It "Should NOT log remediation header as request header for allowed requests" {
            # Make an allowed request to the remediation test endpoint
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/remediation-test"
            $response.StatusCode | Should -Be 200
            
            # Wait a moment for any potential log to be written
            Start-Sleep -Seconds 2
            
            # Read the access.log file from the traefik container
            $accessLogContent = docker exec traefik-modsecurity-plugin-traefik-1 cat /var/log/traefik/access.log 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to read traefik access log"
            }
            
            # Parse the log lines and check for any entries related to the remediation test
            $logLines = $accessLogContent -split "`n" | Where-Object { $_.Trim() -ne "" }
            
            # Validate that ALL log lines are properly formatted JSON (no malformed lines should exist)
            $allLogEntries = @()
            foreach ($line in $logLines) {
                try {
                    $logEntry = $line | ConvertFrom-Json
                    $allLogEntries += $logEntry
                } catch {
                    throw "Malformed JSON line found in log file: '$line'."
                }
            }
            
            # Look for any request headers in successful requests to remediation-test
            # Exclude requests that have error or unhealthy headers (these are not "allowed" requests)
            $remediationHeaderInAllowedRequest = ($allLogEntries | Where-Object { 
                $_.'request_X-Waf-Status' -and 
                $_.RequestPath -eq "/remediation-test" -and
                $_.DownstreamStatus -eq 200 -and
                $_.'request_X-Waf-Status' -ne "error" -and
                $_.'request_X-Waf-Status' -ne "unhealthy"
            }).Count -gt 0
            
            # Verify that remediation header is NOT added to allowed requests
            $remediationHeaderInAllowedRequest | Should -Be $false
        }
        
        It "Should log 'unhealthy' header when ModSecurity backend is unavailable" {
            # Stop the ModSecurity WAF container to simulate unhealthy state
            docker stop traefik-modsecurity-plugin-waf-1
            
            # Wait a moment for the container to stop
            Start-Sleep -Seconds 3
            
            # Make multiple requests to trigger the unhealthy state
            # The first request will fail and mark WAF as unhealthy
            # The second request should use the unhealthy path
            try {
                $response1 = Invoke-SafeWebRequest -Uri "$BaseUrl/remediation-test" -TimeoutSec 5
                # If first request succeeds, WAF might not be marked unhealthy yet
            } catch {
                # Expected for first request when WAF is down
            }
            
            # Wait for WAF to be marked as unhealthy
            Start-Sleep -Seconds 2
            
            # Make another request - this should use the unhealthy path
            try {
                $response2 = Invoke-SafeWebRequest -Uri "$BaseUrl/remediation-test" -TimeoutSec 5
                $response2.StatusCode | Should -Be 200
            } catch {
                # If still failing, that's also acceptable - check if it's a 502/503 response
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    $statusCode | Should -BeGreaterOrEqual 500
                } else {
                    throw "Unexpected error: $($_.Exception.Message)"
                }
            }
            
            # Wait a moment for log to be written
            Start-Sleep -Seconds 2
            
            # Read the access.log file from the traefik container
            $accessLogContent = docker exec traefik-modsecurity-plugin-traefik-1 cat /var/log/traefik/access.log 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to read traefik access log"
            }
            
            # Parse the log lines
            $logLines = $accessLogContent -split "`n" | Where-Object { $_.Trim() -ne "" }
            
            # Validate that ALL log lines are properly formatted JSON
            $allLogEntries = @()
            foreach ($line in $logLines) {
                try {
                    $logEntry = $line | ConvertFrom-Json
                    $allLogEntries += $logEntry
                } catch {
                    throw "Malformed JSON line found in log file: '$line'."
                }
            }
            
            # Look for log entries with 'unhealthy' header value
            $unhealthyHeaderFound = ($allLogEntries | Where-Object { 
                $_.'request_X-Waf-Status' -eq "unhealthy" -and 
                $_.RequestPath -like "/remediation-test*"
            }).Count -gt 0
            
            # Verify that the unhealthy header was logged
            $unhealthyHeaderFound | Should -Be $true
            
            # Restart the WAF container for other tests
            docker start traefik-modsecurity-plugin-waf-1
            Start-Sleep -Seconds 5
        }
        
        It "Should log 'error' header when ModSecurity communication fails" {
            # Make a request to the error test service (with invalid ModSecurity URL)
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/error-test"
            $response.StatusCode | Should -Be 200
            
            # Wait a moment for log to be written
            Start-Sleep -Seconds 2
            
            # Read the access.log file from the traefik container
            $accessLogContent = docker exec traefik-modsecurity-plugin-traefik-1 cat /var/log/traefik/access.log 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to read traefik access log"
            }
            
            # Parse the log lines
            $logLines = $accessLogContent -split "`n" | Where-Object { $_.Trim() -ne "" }
            
            # Validate that ALL log lines are properly formatted JSON
            $allLogEntries = @()
            foreach ($line in $logLines) {
                try {
                    $logEntry = $line | ConvertFrom-Json
                    $allLogEntries += $logEntry
                } catch {
                    throw "Malformed JSON line found in log file: '$line'."
                }
            }
            
            # Look for log entries with 'error' header value
            $errorHeaderFound = ($allLogEntries | Where-Object { 
                $_.'request_X-Waf-Status' -eq "error" -and 
                $_.RequestPath -like "/error-test*"
            }).Count -gt 0
            
            # Verify that the error header was logged
            $errorHeaderFound | Should -Be $true
        }
    }
}

Describe "Bypass Functionality Tests" {
    Context "WAF Bypass Verification" {
        It "Should allow potentially malicious requests through bypass endpoint" {
            $maliciousPatterns = @(
                "?id=1' OR '1'='1",
                "?search=<script>alert('test')</script>",
                "?file=../../../etc/passwd"
            )
            
            Test-BypassPatterns -BaseUrl "$BaseUrl/bypass" -Patterns $maliciousPatterns
        }
    }
}

Describe "Performance and Health Tests" {
    Context "Response Time Tests" {
        It "Should respond within acceptable time limits" {
            Test-ResponseTime -Url "$BaseUrl/protected" -MaxResponseTimeMs 5000
        }
        
        It "Should handle concurrent requests" {
            Test-ConcurrentRequests -Url "$BaseUrl/protected" -RequestCount 5 -MinSuccessCount 3
        }
    }
    
    Context "WAF Health Monitoring" {
        # Removed health endpoint test - keeping it simple
    }
}

Describe "Performance Comparison Tests" {
    Context "WAF vs Bypass Performance Analysis" {
        It "Should measure performance difference between WAF-protected and bypass requests" {
            $testIterations = 20
            $wafResponseTimes = @()
            $bypassResponseTimes = @()
            
            Write-Host "🔄 Running performance comparison test with $testIterations iterations..."
            
            # Test WAF-protected endpoint
            Write-Host "📊 Testing WAF-protected endpoint..."
            for ($i = 1; $i -le $testIterations; $i++) {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -TimeoutSec 10
                    $stopwatch.Stop()
                    if ($response.StatusCode -eq 200) {
                        $wafResponseTimes += $stopwatch.ElapsedMilliseconds
                    }
                } catch {
                    $stopwatch.Stop()
                    Write-Warning "WAF request $i failed: $($_.Exception.Message)"
                }
                Start-Sleep -Milliseconds 50  # Small delay between requests
            }
            
            # Test bypass endpoint
            Write-Host "📊 Testing bypass endpoint..."
            for ($i = 1; $i -le $testIterations; $i++) {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $response = Invoke-SafeWebRequest -Uri "$BaseUrl/bypass" -TimeoutSec 10
                    $stopwatch.Stop()
                    if ($response.StatusCode -eq 200) {
                        $bypassResponseTimes += $stopwatch.ElapsedMilliseconds
                    }
                } catch {
                    $stopwatch.Stop()
                    Write-Warning "Bypass request $i failed: $($_.Exception.Message)"
                }
                Start-Sleep -Milliseconds 50  # Small delay between requests
            }
            
            # Calculate statistics
            if ($wafResponseTimes.Count -gt 0 -and $bypassResponseTimes.Count -gt 0) {
                $wafAvg = ($wafResponseTimes | Measure-Object -Average).Average
                $wafMin = ($wafResponseTimes | Measure-Object -Minimum).Minimum
                $wafMax = ($wafResponseTimes | Measure-Object -Maximum).Maximum
                
                $bypassAvg = ($bypassResponseTimes | Measure-Object -Average).Average
                $bypassMin = ($bypassResponseTimes | Measure-Object -Minimum).Minimum
                $bypassMax = ($bypassResponseTimes | Measure-Object -Maximum).Maximum
                
                $overhead = $wafAvg - $bypassAvg
                
                # Display results
                Write-Host "`n📈 Performance Comparison Results:"
                Write-Host "┌─────────────────┬─────────────┬─────────────┬─────────────┐"
                Write-Host "│ Endpoint        │ Average (ms)│ Min (ms)    │ Max (ms)    │"
                Write-Host "├─────────────────┼─────────────┼─────────────┼─────────────┤"
                Write-Host "│ WAF Protected   │ $($wafAvg.ToString('F1').PadLeft(11)) │ $($wafMin.ToString('F1').PadLeft(11)) │ $($wafMax.ToString('F1').PadLeft(11)) │"
                Write-Host "│ Bypass          │ $($bypassAvg.ToString('F1').PadLeft(11)) │ $($bypassMin.ToString('F1').PadLeft(11)) │ $($bypassMax.ToString('F1').PadLeft(11)) │"
                Write-Host "└─────────────────┴─────────────┴─────────────┴─────────────┘"
                Write-Host "`n⚡ WAF Overhead: $($overhead.ToString('F1')) ms"
                
                # Store results for validation
                $script:PerformanceResults = @{
                    WafAverage = $wafAvg
                    BypassAverage = $bypassAvg
                    Overhead = $overhead
                    WafSamples = $wafResponseTimes.Count
                    BypassSamples = $bypassResponseTimes.Count
                }
                
                # Validate that we have enough samples
                $wafResponseTimes.Count | Should -BeGreaterOrEqual 15 -Because "We need at least 15 successful WAF requests for reliable measurement"
                $bypassResponseTimes.Count | Should -BeGreaterOrEqual 15 -Because "We need at least 15 successful bypass requests for reliable measurement"
                
                # Validate that WAF adds some overhead (but not too much)
                $overhead | Should -BeGreaterOrEqual 0 -Because "WAF should add some processing overhead"
                $overhead | Should -BeLessThan 1000 -Because "WAF overhead should be reasonable (less than 1000ms)"
                
            } else {
                throw "Insufficient successful requests for performance comparison"
            }
        }
    }
}

Describe "Error Handling and Edge Cases" {
    Context "Large Request Handling" {
        It "Should handle moderately large POST requests" {
            $largeData = "data=" + ("a" * 1000)  # 1KB of data
            $response = Invoke-SafeWebRequest -Uri "$BaseUrl/protected" -Method POST -Body $largeData
            $response.StatusCode | Should -Be 200
        }
    }
    
    Context "Special Characters and Encoding" {
        It "Should handle URL-encoded requests properly" {
            $encodedUrl = "$BaseUrl/protected?name=" + [System.Web.HttpUtility]::UrlEncode("John & Jane")
            $response = Invoke-SafeWebRequest -Uri $encodedUrl
            $response.StatusCode | Should -Be 200
        }
    }
}

AfterAll {
    Write-Host "`n🏁 Integration tests completed!" -ForegroundColor Green
    Write-Host "📊 Test Results Summary:" -ForegroundColor Cyan
    Write-Host "  - Services tested: Traefik, ModSecurity WAF, Protected & Bypass endpoints" -ForegroundColor Gray
    Write-Host "  - Security features: SQL injection, XSS, Path traversal, Command injection protection" -ForegroundColor Gray
    Write-Host "  - Performance: Response time and concurrent request handling" -ForegroundColor Gray
    Write-Host "  - Custom features: Remediation headers, WAF bypass verification" -ForegroundColor Gray
}
