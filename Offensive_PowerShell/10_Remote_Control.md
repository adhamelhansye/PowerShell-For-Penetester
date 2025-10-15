### Enabling PowerShell Remoting

**Command:**

```powershell
Enable-PSRemoting -Force
```

**Description:**

Enables PowerShell remoting on the target machine by configuring the WinRM service to accept remote PowerShell commands. The `-Force` parameter overwrites existing configurations if needed.

**Example:**

Enable remoting on the local machine to allow remote connections.

---

### Configuring WinRM

**Script/Command:**

```powershell
$thumbprint = (New-SelfSignedCertificate -DnsName localhost -CertStoreLocation Cert:\LocalMachine\My).Thumbprint
winrm create winrm/config/Listener?Address=*+Transport=HTTPS '@{Hostname="localhost";CertificateThumbprint="$thumbprint"}'
```

**Description:**

Configures WinRM to use HTTPS with a self-signed certificate for secure communication. Creates a self-signed certificate and sets up a listener with the certificate's thumbprint.

**Example:**

Set up an HTTPS listener on the local machine using a self-signed certificate.

---

### Connecting to a Remote Machine

**Command:**

```powershell
Enter-PSSession -ComputerName <RemoteComputer>
```

**Description:**

Establishes an interactive PowerShell session on the specified remote computer, allowing direct command execution as if on the target machine.

**Example:**

Connect to a remote machine named "powershell.snowcapcyber.com":

```powershell
Enter-PSSession -ComputerName powershell.snowcapcyber.com
```

---

### Executing Commands on Remote Machines

**Command:**

```powershell
Invoke-Command -ComputerName <RemoteComputer> -ScriptBlock { Get-Process }
```

**Description:**

Executes a command (e.g., `Get-Process`) on the specified remote computer using the `Invoke-Command` cmdlet.

**Example:**

Retrieve process information from "powershell.snowcapcyber.com":

```powershell
Invoke-Command -ComputerName powershell.snowcapcyber.com -ScriptBlock { Get-Process }
```

---

### Remoting with Credentials and Sessions

**Script/Command:**

```powershell
$RemoteComputer = "powershell.snowcapcyber.com"
$session = New-PSSession -ComputerName $RemoteComputer
Invoke-Command -Session $session -ScriptBlock { Get-Process }
Remove-PSSession -Session $session
```

**Description:**

Creates a PowerShell session on a remote machine, executes a command (e.g., `Get-Process`), and closes the session. The `New-PSSession` cmdlet establishes the session, and `Remove-PSSession` cleans it up.

**Example:**

Create and use a session on "powershell.snowcapcyber.com":

```powershell
$RemoteComputer = "powershell.snowcapcyber.com"
$session = New-PSSession -ComputerName $RemoteComputer
Invoke-Command -Session $session -ScriptBlock { Get-Process }
Remove-PSSession -Session $session
```

---

### Configuring Trusted Hosts

**Command:**

```powershell
Set-Item wsman:\localhost\Client\TrustedHosts -Value <RemoteComputer> -Force
```

**Description:**

Adds a remote computer to the list of trusted hosts for secure communication in trusted network environments. The `-Force` parameter overwrites existing settings.

**Example:**

Add "powershell.snowcapcyber.com" to the trusted hosts list:

```powershell
Set-Item wsman:\localhost\Client\TrustedHosts -Value powershell.snowcapcyber.com -Force
```

---

### Session Configuration and Persistent Sessions

**Script/Command:**

```powershell
$session = New-PSSession -ComputerName <RemoteComputer>
Invoke-Command -Session $session -ScriptBlock { Get-Process }
```

**Description:**

Creates a persistent PowerShell session on a remote machine and uses it to execute commands, allowing multiple interactions without re-establishing the session.

**Example:**

Create a persistent session on "powershell.snowcapcyber.com":

```powershell
$session = New-PSSession -ComputerName powershell.snowcapcyber.com
Invoke-Command -Session $session -ScriptBlock { Get-Process }
```

---

### Parallel Remoting

**Command:**

```powershell
$computers = "<RemoteComputer1>", "<RemoteComputer2>", "<RemoteComputer3>"
Invoke-Command -ComputerName $computers -ScriptBlock { Get-Process } -ThrottleLimit 3
```

**Description:**

Executes commands in parallel on multiple remote machines, with the `-ThrottleLimit` parameter controlling the number of concurrent connections.

**Example:**

Retrieve process information from three machines simultaneously:

```powershell
$computers = "server1", "server2", "server3"
Invoke-Command -ComputerName $computers -ScriptBlock { Get-Process } -ThrottleLimit 3
```

---

### Remote Variable Usage

**Command:**

```powershell
$remoteVar = "Hello from remote"
Invoke-Command -ComputerName <RemoteComputer> -ScriptBlock { Write-Host $using:remoteVar }
```

**Description:**

Uses a local variable in a remote session with the `$using:` scope modifier, allowing data to be passed from the local to the remote context.

**Example:**

Pass a variable to "powershell.snowcapcyber.com":

```powershell
$remoteVar = "Hello from remote"
Invoke-Command -ComputerName powershell.snowcapcyber.com -ScriptBlock { Write-Host $using:remoteVar }
```

---

### Remote Script Execution

**Command:**

```powershell
Invoke-Command -ComputerName <RemoteComputer> -FilePath C:\Scripts\RemoteScript.ps1
```

**Description:**

Executes a specified script file on a remote machine, enabling automation of complex tasks.

**Example:**

Run a script on "powershell.snowcapcyber.com":

```powershell
Invoke-Command -ComputerName powershell.snowcapcyber.com -FilePath C:\Scripts\RemoteScript.ps1
```

---

### Handling Background Jobs

**Script/Command:**

```powershell
$scriptBlock = {
    Get-Process
    Start-Sleep -Seconds 5
    Get-Service
}
$job = Invoke-Command -ComputerName <RemoteComputer> -ScriptBlock $scriptBlock -AsJob
Receive-Job -Job $job
```

**Description:**

Executes a script block as a background job on a remote machine, allowing asynchronous execution and result retrieval.

**Example:**

Run a background job on "powershell.snowcapcyber.com":

```powershell
$scriptBlock = {
    Get-Process
    Start-Sleep -Seconds 5
    Get-Service
}
$job = Invoke-Command -ComputerName powershell.snowcapcyber.com -ScriptBlock $scriptBlock -AsJob
Receive-Job -Job $job
```

---

### Remote Registry Manipulation

**Command:**

```powershell
Invoke-Command -ComputerName <RemoteComputer> -ScriptBlock {
    Set-ItemProperty -Path "HKLM:\Software\Example" -Name "Setting" -Value "NewValue"
}
```

**Description:**

Modifies a registry key on a remote machine, demonstrating remote configuration capabilities.

**Example:**

Update a registry key on "powershell.snowcapcyber.com":

```powershell
Invoke-Command -ComputerName powershell.snowcapcyber.com -ScriptBlock {
    Set-ItemProperty -Path "HKLM:\Software\Example" -Name "Setting" -Value "NewValue"
}
```

---

### Remote Event Log Retrieval

**Command:**

```powershell
Get-WinEvent -ComputerName <RemoteComputer> -LogName System -MaxEvents 10
```

**Description:**

Retrieves a specified number of recent event log entries from the System log on a remote machine.

**Example:**

Get the 10 most recent System events from "powershell.snowcapcyber.com":

```powershell
Get-WinEvent -ComputerName powershell.snowcapcyber.com -LogName System -MaxEvents 10
```

---

### Remote Service Management

**Command:**

```powershell
Invoke-Command -ComputerName <RemoteComputer> -ScriptBlock { Stop-Service -Name Spooler }
```

**Description:**

Manages services on a remote machine, such as stopping the specified service.

**Example:**

Stop the Spooler service on "powershell.snowcapcyber.com":

```powershell
Invoke-Command -ComputerName powershell.snowcapcyber.com -ScriptBlock { Stop-Service -Name Spooler }
```

---

### Remote Software Installation

**Script/Command:**

```powershell
$computers = "<RemoteComputer1>", "<RemoteComputer2>", "<RemoteComputer3>"
$softwarePath = "\\FileServer\Software\InstallScript.ps1"
Invoke-Command -ComputerName $computers -ScriptBlock {
    param($path)
    Invoke-Expression (Get-Content $path -Raw)
} -ArgumentList $softwarePath
```

**Description:**

Installs software on multiple remote machines by executing a script from a file server.

**Example:**

Install software on "server1", "server2", and "server3":

```powershell
$computers = "server1", "server2", "server3"
$softwarePath = "\\FileServer\Software\InstallScript.ps1"
Invoke-Command -ComputerName $computers -ScriptBlock {
    param($path)
    Invoke-Expression (Get-Content $path -Raw)
} -ArgumentList $softwarePath
```

---

### Remoting to Azure Virtual Machines

**Command:**

```powershell
$cred = Get-Credential
Enter-PSSession -HostName "<AzureVMName>.cloudapp.net" -Credential $cred -UseSSL
```

**Description:**

Establishes a secure remote session to an Azure VM using specified credentials and SSL.

**Example:**

Connect to an Azure VM named "myazurevm":

```powershell
$cred = Get-Credential
Enter-PSSession -HostName "myazurevm.cloudapp.net" -Credential $cred -UseSSL
```

---

### Remote Network Configuration

**Command:**

```powershell
Invoke-Command -ComputerName <RemoteComputer> -ScriptBlock {
    New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "192.168.1.100" -PrefixLength 24
}
```

**Description:**

Configures network settings, such as setting a new IP address, on a remote machine.

**Example:**

Set an IP address on "powershell.snowcapcyber.com":

```powershell
Invoke-Command -ComputerName powershell.snowcapcyber.com -ScriptBlock {
    New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "192.168.1.100" -PrefixLength 24
}
```

---

### Remote User Management

**Command:**

```powershell
Invoke-Command -ComputerName <RemoteComputer> -ScriptBlock {
    New-LocalUser -Name "NewUser" -Password (ConvertTo-SecureString "Password123" -AsPlainText) -FullName "New User"
}
```

**Description:**

Creates a new local user account on a remote machine.

**Example:**

Create a user on "powershell.snowcapcyber.com":

```powershell
Invoke-Command -ComputerName powershell.snowcapcyber.com -ScriptBlock {
    New-LocalUser -Name "NewUser" -Password (ConvertTo-SecureString "Password123" -AsPlainText) -FullName "New User"
}
```

---

### Remote File Copy

**Command:**

```powershell
$sourcePath = "C:\LocalPath\File.txt"
$destinationPath = "\\RemoteComputer\C$\RemotePath"
Copy-Item -Path $sourcePath -Destination $destinationPath
```

**Description:**

Copies a file from the local machine to a remote machine using the administrative share (e.g., `C$`).

**Example:**

Copy a file to "powershell.snowcapcyber.com":

```powershell
$sourcePath = "C:\LocalPath\File.txt"
$destinationPath = "\\powershell.snowcapcyber.com\C$\RemotePath"
Copy-Item -Path $sourcePath -Destination $destinationPath
```.
