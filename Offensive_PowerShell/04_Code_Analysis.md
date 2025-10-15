### 04\_Code\_Analysis.md

# 04 - Analyzing .NET Assemblies for Vulnerabilities 🕵️

PowerShell can be used to perform static analysis on files for sensitive information before they are compiled or to analyze deployed binaries.

### Scanning Assemblies for Hardcoded Credentials

Penetration Testers can use PowerShell for file I/O operations and **Regular Expressions** to scan assemblies (like DLLs or EXEs) for sensitive API Keys or hardcoded Credentials.

```powershell
$assemblyPath = "C:\MyData\Assembly.dll"

# Read the entire file content as a single string
$strings = [System.IO.File]::ReadALLText($assemblyPath) 

# Simple regex pattern to find strings that look like API Keys
$apikey = "API_KEY=[A-Za-z0-9]"

# Find all matches of the pattern in the assembly content
$matches = [System.Text.RegularExpressions.Regex]::Matches($strings,$apikey)

Write-Host "Potential API Keys Found : "
foreach ($match in $match) {
    Write-Host $match.Value
}
```
