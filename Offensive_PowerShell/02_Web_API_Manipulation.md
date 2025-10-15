PowerShell is excellent for interacting with web services, often used to automate checks against internal APIs or communicate with a C2 server.

### Retrieving JSON data from Web APIs

`Invoke-RestMethod` is the workhorse for HTTP requests, automatically parsing JSON or XML responses.

```powershell
$url = "https://api.snowcapcyber.com/repo"
$response = Invoke-RestMethod -Uri $url

# Parsing JSON Data -> Use ConvertFrom-Json
$repoObject = ConvertFrom-Json $response # Converts the JSON string into a PowerShell object
Write-Host "Repo Name : $($repoObject.name)"
Write-Host "Description : $($repoObject.description)"
```

### JSON Manipulation for Payloads

Used to craft custom payloads for API fuzzing or authenticated requests.

```powershell
# Create a PowerShell Hash Table
$payload = @{
	"username" = "admin"
	"password" = "Password"
} | ConvertTo-Json # Converts the object into a valid JSON string for transmission

$headers = @{
	"Content-Type" = "application/json" # Tells the server how to interpret the body
}

# Perform the POST request
Invoke-RestMethod -Uri "URL here" -Method POST -Body $payload -Headers $headers
```
