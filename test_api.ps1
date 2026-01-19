# Test the HTTP Observatory API running in Docker

# 1. Ensure the container is running with port mapping:
# docker run -d -p 3000:3000 httpobs-rust

$BaseUrl = "http://localhost:3000"

Write-Host "Checking API Version..."
try {
    $Version = Invoke-RestMethod -Uri "$BaseUrl/__version__" -Method Get
    Write-Host "Success! Version: $Version" -ForegroundColor Green
} catch {
    Write-Host "Failed to connect. Make sure Docker is running with '-p 3000:3000'." -ForegroundColor Red
    exit
}

Write-Host "`nchecking Heartbeat..."
try {
    $Heartbeat = Invoke-RestMethod -Uri "$BaseUrl/__heartbeat__" -Method Get
    Write-Host "Heartbeat: $Heartbeat" -ForegroundColor Green
} catch {
    Write-Host "Heartbeat failed." -ForegroundColor Red
}

Write-Host "`n(Optional) Triggering a Scan..."
try {
    # Note: Requires DB to be connected for full functionality, 
    # but let's test the endpoint reachability.
    $Params = @{ host = "example.com" }
    $Scan = Invoke-RestMethod -Uri "$BaseUrl/api/v1/analyze" -Method Post -Body $Params
    Write-Host "Scan Initiated: $($Scan | ConvertTo-Json -Depth 2)" -ForegroundColor Green
} catch {
    Write-Host "Scan trigger returned error (Expected if DB is missing): $($_.Exception.Message)" -ForegroundColor Yellow
}
