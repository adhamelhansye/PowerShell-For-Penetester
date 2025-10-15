### FTP Server

**Script/Command:**

```powershell
$ftpServer = "ftp://ftp.snowcapcyber.com"
$request = [System.Net.WebRequest]::Create($ftpServer)
$request.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails
$response = $request.GetResponse()
$stream = $response.GetResponseStream()
$reader = [System.IO.StreamReader]::new($stream)
$banner = $reader.ReadToEnd()
Write-Host "Banner Information:"
Write-Host $banner
$reader.Close()
$response.Close()
```

**Description:**

Performs banner grabbing by connecting to the FTP server and retrieving details about the service, including its type and version, to identify potential vulnerabilities.

**Example:**

Retrieve banner information from ftp.snowcapcyber.com to check the software version.

---

**Script/Command:**

```powershell
$ftpServer = "ftp://ftp.snowcapcyber.com"
$ftpUsername = "your_username"
$ftpPassword = "your_password"
$ftpWebRequest = [System.Net.FtpWebRequest]::Create($ftpServer)
$ftpWebRequest.Credentials = New-Object System.Net.NetworkCredential($ftpUsername, $ftpPassword)
$ftpResponse = $ftpWebRequest.GetResponse()
```

**Description:**

Establishes a TCP connection to the FTP server using the specified credentials.

**Example:**

Connect to ftp.snowcapcyber.com with username "your_username" and password "your_password".

---

**Script/Command:**

```powershell
$ftpServer = "ftp://ftp.snowcapcyber.com"
$webClient = New-Object System.Net.WebClient
$credentials = $webClient.Credentials
if ($credentials.UserName -eq "anonymous" -or $credentials.UserName -eq "") {
    Write-Host "Anonymous access is enabled."
} else {
    Write-Host "Anonymous access is disabled."
}
```

**Description:**

Checks if the FTP server allows anonymous access, which can indicate a security risk.

**Example:**

Test ftp.snowcapcyber.com to see if anonymous login is permitted.

---

**Script/Command:**

```powershell
$ftpServer = "ftp://ftp.snowcapcyber.com"
$request = [System.Net.WebRequest]::Create($ftpServer)
$request.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails
$request.EnableSsl = $true
try {
    $response = $request.GetResponse()
    Write-Host "SSL/TLS is supported."
    $response.Close()
} catch {
    Write-Host "SSL/TLS is not supported or misconfigured."
}
```

**Description:**

Verifies if the FTP server supports SSL/TLS for secure connections.

**Example:**

Check if ftp.snowcapcyber.com supports SSL/TLS encryption.

---

**Script/Command:**

```powershell
$ftpServer = "ftp://ftp.snowcapcyber.com"
$ftpUsername = "ajcblyth"
$ftpPassword = "Th1s1sMyOa55w9rd"
$remoteDirectory = "/home/ajcblyth/directory"
$ftpWebRequest = [System.Net.FtpWebRequest]::Create("$ftpServer$remoteDirectory")
$ftpWebRequest.Credentials = New-Object System.Net.NetworkCredential($ftpUsername, $ftpPassword)
$ftpWebRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
$ftpResponse = $ftpWebRequest.GetResponse()
```

**Description:**

Lists files in a specified directory on the FTP server.

**Example:**

List files in /home/ajcblyth/directory on ftp.snowcapcyber.com.

---

**Script/Command:**

```powershell
$ftpServer = "ftp://ftp.snowcapcyber.com"
$ftpUsername = "ajcblyth"
$ftpPassword = ".Th1s1sMyOa55w9rd"
$localFilePath = "C:\local\file.txt"
$remoteFilePath = "/remote/directory/file.txt"
$ftpWebRequest = [System.Net.FtpWebRequest]::Create("$ftpServer$remoteFilePath")
$ftpWebRequest.Credentials = New-Object System.Net.NetworkCredential($ftpUsername, $ftpPassword)
$ftpWebRequest.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
$fileContent = Get-Content $localFilePath
$ftpRequestStream = $ftpWebRequest.GetRequestStream()
$ftpRequestStream.Write($fileContent, 0, $fileContent.Length)
$ftpRequestStream.Close()
$ftpResponse = $ftpWebRequest.GetResponse()
```

**Description:**

Uploads a local file to the specified location on the FTP server.

**Example:**

Upload C:\local\file.txt to /remote/directory/file.txt on ftp.snowcapcyber.com.

---

**Script/Command:**

```powershell
$ftpServer = "ftp://ftp.snowcapcyber.com"
$ftpUsername = "ajcblyth"
$ftpPassword = ".Th1s1sMyOa55w9rd"
$remoteFilePath = "/remote/directory/file.txt"
$localFilePath = "C:\local\downloaded_file.txt"
$ftpWebRequest = [System.Net.FtpWebRequest]::Create("$ftpServer$remoteFilePath")
$ftpWebRequest.Credentials = New-Object System.Net.NetworkCredential($ftpUsername, $ftpPassword)
$ftpWebRequest.Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile
$ftpResponse = $ftpWebRequest.GetResponse()
$ftpResponseStream = $ftpResponse.GetResponseStream()
$fileStream = [System.IO.File]::Create($localFilePath)
$buffer = New-Object byte[] 1024
while ($true) {
    $read = $ftpResponseStream.Read($buffer, 0, $buffer.Length)
    if ($read -le 0) {
        break
    }
    $fileStream.Write($buffer, 0, $read)
}
$fileStream.Close()
$ftpResponseStream.Close()
```

**Description:**

Downloads a file from the FTP server to a local directory.

**Example:**

Download /remote/directory/file.txt from ftp.snowcapcyber.com to C:\local\downloaded_file.txt.

---

**Script/Command:**

```powershell
$ftpServer = "ftp://ftp.snowcapcyber.com"
$ftpUsername = "ajcblyth"
$passwords = "password1", "password123", "ftpuserpass", "secureftp"
$webClient = New-Object System.Net.WebClient
$failedAttempts = 0
foreach ($password in $passwords) {
    $webClient.Credentials = New-Object System.Net.NetworkCredential($ftpUsername, $password)
    try {
        $webClient.UploadFile("$ftpServer/test.txt", "C:\temp\test.txt")
        Write-Host "Password '$password' worked!"
        break
    } catch {
        $failedAttempts++
    }
}
if ($failedAttempts -eq $passwords.Count) {
    Write-Host "No valid password found."
}
```

**Description:**

Tests password strength by attempting to brute-force authentication with a list of passwords (requires authorization).

**Example:**

Test passwords password1, password123, ftpuserpass, and secureftp for ajcblyth on ftp.snowcapcyber.com.

---

**Script/Command:**

```powershell
Test-NetConnection -ComputerName ftp.snowcapcyber.com -Port 21
```

**Description:**

Checks if the FTP server is accessible on port 21 to assess firewall and access control configurations.

**Example:**

Verify connectivity to ftp.snowcapcyber.com on the default FTP port.

---

### TFTP Server

**Script/Command:**

```powershell
Test-NetConnection -ComputerName tftp.snowcapcyber.com -Port 69
```

**Description:**

Identifies the TFTP server by checking if port 69 is open.

**Example:**

Confirm if tftp.snowcapcyber.com is running a TFTP service.

---

**Script/Command:**

```powershell
Install-Module -Name PSFTP
Get-PSFTPConfiguration -ComputerName tftp.snowcapcyber.com
```

**Description:**

Enumerates the TFTP server configuration, including allowed transfer modes and restrictions.

**Example:**

Retrieve configuration details for tftp.snowcapcyber.com.

---

**Script/Command:**

```powershell
# Specify the path to the file
$filePath = "C:\Path\To\Your\TFTPFile.txt"
$computer = "tftp.snowcapcyber.com"
# Check if the file exists
if (Test-Path $filePath -PathType Leaf) {
    # Read the contents of the file and print each line
    Get-Content $filePath | ForEach-Object {
        Get-PSFTPFile -ComputerName $computer -Path $_
    }
} else {
    Write-Host "File not found: $filePath"
}
```

**Description:**

Verifies access controls by attempting to retrieve a series of files listed in a text file.

**Example:**

Try to retrieve files listed in C:\Path\To\Your\TFTPFile.txt from tftp.snowcapcyber.com.

---

### SSH, SCP, and SFTP

**Script/Command:**

```powershell
Invoke-Command -ComputerName ssh.snowcapcyber.com -ScriptBlock { ssh -V }
```

**Description:**

Retrieves the SSH server version to identify potential vulnerabilities.

**Example:**

Check the version of ssh.snowcapcyber.com.

---

**Script/Command:**

```powershell
Invoke-Command -ComputerName ssh.snowcapcyber.com -ScriptBlock { ssh -Q kex }
```

**Description:**

Queries the SSH server for supported key exchange algorithms.

**Example:**

List key exchange algorithms supported by ssh.snowcapcyber.com.

---

**Script/Command:**

```powershell
Invoke-Command -ComputerName ssh.snowcapcyber.com -ScriptBlock { ssh -Q cipher }
```

**Description:**

Queries the SSH server for supported encryption algorithms.

**Example:**

List encryption ciphers supported by ssh.snowcapcyber.com.

---

**Script/Command:**

```powershell
Invoke-Command -ComputerName ssh.snowcapcyber.com -ScriptBlock { ssh -Q auth }
```

**Description:**

Queries the SSH server for supported authentication methods.

**Example:**

List authentication methods supported by ssh.snowcapcyber.com.

---

**Script/Command:**

```powershell
Invoke-Command -ComputerName ssh.snowcapcyber.com -ScriptBlock { Get-Content /etc/ssh/sshd_config }
```

**Description:**

Retrieves the SSH server configuration file for security settings review.

**Example:**

Analyze the sshd_config file on ssh.snowcapcyber.com.

---

**Script/Command:**

```powershell
Invoke-Command -ComputerName ssh.snowcapcyber.com -ScriptBlock { cat /etc/ssh/sshd_config | grep AllowUsers }
```

**Description:**

Extracts user access control settings from the SSH configuration file.

**Example:**

Check allowed users on ssh.snowcapcyber.com.

---

**Script/Command:**

```powershell
Invoke-Command -ComputerName scp.snowcapcyber.com -ScriptBlock { scp -V }
```

**Description:**

Verifies if SCP is supported by checking its version.

**Example:**

Check SCP version on scp.snowcapcyber.com.

---

**Script/Command:**

```powershell
Invoke-Command -ComputerName sftp.snowcapcyber.com -ScriptBlock { sftp -V }
```

**Description:**

Retrieves the SFTP subsystem version to identify vulnerabilities.

**Example:**

Check SFTP version on sftp.snowcapcyber.com.

---

**Script/Command:**

```powershell
Invoke-Command -ComputerName www.snowcapcyber.com -ScriptBlock { Get-Content /etc/ssh/sshd_config | grep Subsystem }
```

**Description:**

Reviews SFTP configuration settings from the SSH configuration file.

**Example:**

Check SFTP subsystem settings on www.snowcapcyber.com.

---

**Script/Command:**

```powershell
Invoke-Command -ComputerName ssh.snowcapcyber.com -ScriptBlock { ssh-audit ssh.snowcapcyber.com }
```

**Description:**

Uses the ssh-audit tool to perform a security audit on the SSH server.

**Example:**

Audit ssh.snowcapcyber.com for security recommendations.

---

**Script/Command:**

```powershell
# Invoke SSH command on the remote server using the private key
Invoke-Command -ComputerName ssh.snowcapcyber.com -ScriptBlock {
    param($sshKey)
    ssh -T -i $using:sshKey ajcblyth@ssh.snowcapcyber.com
} -ArgumentList $sshKey
```

**Description:**

Validates SSH key authentication for a user.

**Example:**

Test SSH key authentication for ajcblyth on ssh.snowcapcyber.com.

---

**Script/Command:**

```powershell
Invoke-Command -ComputerName ssh.snowcapcyber.com -ScriptBlock { sudo -l }
```

**Description:**

Checks the sudo privileges of the user on the SSH server.

**Example:**

Verify sudo permissions on ssh.snowcapcyber.com.

---

**Script/Command:**

```powershell
Invoke-Command -ComputerName ssh.snowcapcyber.com -ScriptBlock { Get-EventLog -LogName Security -Source sshd }
```

**Description:**

Retrieves SSH-related events from the Security log for monitoring and auditing.

**Example:**

Review security logs for sshd on ssh.snowcapcyber.com.

---

**Script/Command:**

```powershell
# Install Posh-SSH module
Install-Module -Name Posh-SSH -Force -AllowClobber
# Import the module
Import-Module Posh-SSH
# Example: Establish an SSH session
$session = New-SSHSession -Port 22 -ComputerName ssh.snowcapcyber.com -Credential (Get-Credential)
# Example: Run a command on the remote server
Invoke-SSHCommand -SessionId $session.SessionId -Command "ls -l"
# Example: Close the SSH session
Remove-SSHSession -SessionId $session.SessionId
```

**Description:**

Uses the Posh-SSH module to establish an SSH session, execute commands, and manage the session.

**Example:**

Connect to ssh.snowcapcyber.com, run "ls -l", and close the session.

---

**Script/Command:**

```powershell
# Example: Using WinSCP .NET Assembly for SFTP
$sessionOptions = New-Object WinSCP.SessionOptions -Property @{
    Protocol = [WinSCP.Protocol]::Sftp
    HostName = "ssh.snowcapcyber.com"
    UserName = "ajcblyth"
    Password = "MyPa55w0RdL3tM31N"
}
$session = New-Object WinSCP.Session
try {
    $session.Open($sessionOptions)
    $session.GetFiles("/remote/path/*.txt", "C:\local\path\").Check()
}
finally {
    $session.Dispose()
}
```

**Description:**

Uses the WinSCP .NET assembly to perform SFTP file transfers.

**Example:**

Download *.txt files from /remote/path on ssh.snowcapcyber.com to C:\local\path\.

---

**Script/Command:**

```powershell
# Install SSH-Sessions module
Install-Module -Name SSH-Sessions -Force -AllowClobber
# Import the module
Import-Module SSH-Sessions
# Example: Establish a persistent SSH session
$session = New-SshSession -ComputerName ssh.snowcapcyber.com -Credential (Get-Credential)
# Example: Run a command on the remote server
Invoke-SshCommand -SessionId $session.SessionId -Command "ls -l"
# Example: Close the persistent SSH session
Remove-SshSession -SessionId $session.SessionId
```

**Description:**

Uses the SSH-Sessions module to create and manage persistent SSH sessions.

**Example:**

Establish a persistent session with ssh.snowcapcyber.com, run "ls -l", and close it.

---

**Script/Command:**

```powershell
# Example: Using Chilkat SSH/SFTP Module
$ssh = New-Object Chilkat.Ssh
$success = $ssh.Connect("ssh.snowcapcyber.com")
if ($success -eq $true) {
    $ssh.AuthenticatePw("ajcblyth", "MyPa55w0RdL3tM31N")
    $commandResult = $ssh.QuickCmd("ls -l")
    Write-Host $commandResult
}
$ssh.Disconnect()
```

**Description:**

Uses the Chilkat PowerShell SSH/SFTP module to connect and execute commands.

**Example:**

Connect to ssh.snowcapcyber.com, authenticate as ajcblyth, and run "ls -l".

---
