#  Module Management and Execution Policy 

PowerShell modules are key for offensive operations, providing specialized cmdlets (functions) like those in the popular **PowerSploit** framework.

### Execution Policy

The execution policy is a safety feature that controls which scripts PowerShell can run. A common first step for an attacker after gaining access is changing this policy.

**View Policy:**

```powershell
Get-ExecutionPolicy -List
```

**Enable Script Execution:** To enable PowerShell execution **on a target system after hacking**:

```powershell
Set-ExecutionPolicy Unrestricted # Highly insecure, but common in testing/attacks
```

*Note: `Unrestricted` allows all scripts to run without signing, posing a huge security risk.*

### Finding and Installing Modules

Once PowerShell is enabled, you need to identify and install modules containing useful cmdlets.

  * **List Available Modules:** Use `Find-Module` to search the PowerShell Gallery for modules by tag.
    ```powershell
    # Search for modules related to SSH
    Find-Module -Tag SSH
    ```
  * **Install a Module:** Download and install a module using the `Install-Module` command.
    ```powershell
    Install-Module -Name SSH
    ```
    *Note: `Install-Module` typically requires administrator privileges.*

### Importing and Using Modules

  * **Import Functions:** Load a local module (like one from a payload framework) into the current session.
    ```powershell
    Import-Module .\PowerSploit.psd1 # The .psd1 file is the module manifest
    ```
  * **Identify Functions/Cmdlets:** Use `Get-Command` to identify the cmdlets available in the imported module.
    ```powershell
    Get-Command -Module SSH # Lists all functions, cmdlets, and aliases
    ```
