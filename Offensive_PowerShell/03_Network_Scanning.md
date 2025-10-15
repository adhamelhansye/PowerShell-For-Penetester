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

### DNS Vulnerability Testing

This script tests for simple DNS spoofing by checking if a target domain resolves to an unexpected malicious IP address.

```powershell
$DNS_Server = "192.168.1.1" # The specific DNS server to test
$Malicious_IP = "10.10.10.10" # The IP the attacker expects the domain to resolve to
$Target_Domain = "snowcapcyber.com"

# Test if the specified DNS Server resolves the domain to the malicious IP
$DNS_Response = Test-DnsServer -IPAddress $DNS_Server -Name $Target_Domain -Type A
if ($DNS_Response.QueryResults.IPAddress -eq $Malicious_IP){
	Write-Host "Server Vulnerable to Spoofing: Target domain resolves to $Malicious_IP"
} else { 
	Write-Host "DNS Server is not Vulnerable (or resolves to a different IP)" 
}
```
