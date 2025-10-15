# 03 - Network Scanning and DNS Testing 

### Single Port Scanning with Test-NetConnection

`Test-NetConnection` (`tnc`) is a native, firewall-friendly cmdlet used to check network connectivity, serving as a basic port scanner.

```powershell
# Checks if the remote host (192.168.1.100) is listening on TCP port 80
Test-NetConnection -ComputerName 192.168.1.100 -Port 80 
```

### Multiple Port Scanning with Test-NetConnection

By looping through a list of common ports, you can perform a quick service enumeration.

```powershell
$RemoteHost = "192.168.100.21"
$Ports = 80,443,22,21 # HTTP, HTTPS, SSH, FTP
foreach ($port in $Ports) {
    # The output will include TcpTestSucceeded: True/False
    Test-NetConnection -ComputerName $RemoteHost -Port $port 
}
```
