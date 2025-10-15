# 01 - Information Gathering with PowerShell

### Using WMI for System Information Gathering

**WMI (Windows Management Instrumentation)** is a powerful, native Windows management technology. Attackers love it because it can be used for local and remote data collection without installing new software, making it **"Living off the Land" (LotL)**.

```powershell
# Get installed software list. Win32_Product is slow and can be unstable, 
# but effectively enumerates installed software.
$softwarelist = Get-WmiObject -Class Win32_Product |
Select-Object -Property Name,Vendor,Version # Selects only the needed properties

foreach ($software in $softwarelist) {
    Write-Host "Name : $($software.Name)"
    Write-Host "Vendor : $($software.Vendor)"
    Write-Host "Version : $($software.Version)"
    Write-Host ""
}
```

### WMI for Network Information

Gathering network details helps an attacker map the internal network and identify pivot points.

```powershell
# Get network adapter configuration and filter out adapters without an IP (e.g., disconnected ones)
$network = Get-WmiObject -Class Win32_NetworkAdapterConfiguration |
Where-Object { $_.IPAddress -ne $null } # Filters to only adapters with an IP Address

foreach ($adapter in $network) {
    Write-Host "Adapter Description: $($adapter.Description)"
    # IPAddress is an array, so we take the first element (index 0)
    Write-Host "IP Address : $($adapter.IPAddress[0])"
    Write-Host "MAC Address: $($adapter.MACAddress)"
    Write-Host ""
}
```

-----
