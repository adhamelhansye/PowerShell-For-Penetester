# PowerShell for Penetration Testers 

PowerShell is a powerful tool for system administration and, consequently, a valuable asset for penetration testers, as it is native to the Windows environment.

### What is PowerShell?

  * **For Microsoft (MS):** Windows PowerShell is a task-based command-line shell and scripting language designed especially for system administration. It is built on the .NET Framework and helps IT professionals automate the administration of the Windows operating system and its applications.
  * **For Penetration Testers:** PowerShell acts as a shell and scripting language already present on most general targets in a penetration test. It is considered the **"bash of Windows"** and is powerful for:
      * Easy **post-exploitation**.
      * A powerful method to **"reside"** in systems and networks.
      * Reducing the reliance on Metasploit (`msf`) and Linux scripting to executable libraries.

### Why Use PowerShell?

PowerShell is tightly integrated with Windows and is highly effective for an attacker because it:

  * Provides access to **almost everything in a Windows platform**.
  * Is easy to learn and powerful.
  * Is based on the **.NET framework** and is **tightly integrated with Windows**.
  * Is **trusted by countermeasures** and system administrators, making it a low-suspicion tool.

## Core Components

### Cmdlets

Cmdlets (pronounced "command-lets") are task-based commands that form the **"heart-and-soul of PowerShell."** Many interesting cmdlets exist from a pentester's perspective.

### PowerShell Scripting

PowerShell scripts are powerful, often accomplishing much work in fewer lines of code.

  * Scripts can use **cmdlets, native commands, functions, .NET, DLLs, WMI, and much more** in a single program.
  * The syntax is easy.
  * **Variables** are declared in the form **`$<variable>`**.
      * They can hold command output, objects, and values.
      * The variable type does not need to be specified (e.g., `$directories = Get-ChildItem` is a valid statement).
  * *Security Note:* As a security measure, PowerShell scripts by default **do not execute if you double-click** them.

### Modules

A module is essentially a script with the extension **`.psm1`**, which is great for code reuse.

  * You can create a module by simply renaming a script to `.psm1` (e.g., `copy .\script_ex.ps1 .\module_ex.psm1`).
  * Use `Get-Module –ListAvailable` to list all available modules.
  * Use `Import-Module <modulename | modulepath>` to import a module.
  * You can control what functions are exposed in a module using `Export-ModuleMember`.

## Accessing the Registry 💾

PowerShell treats the Registry as a drive because of the **Registry psprovider**. This provides a very easy and powerful way to access the Registry.

### Accessing Keys and Values

  * **Default Hives:** `HKLM` (HKEY\_LOCAL\_MACHINE) and `HKCU` (HKEY\_CURRENT\_USER) are available by default.
  * **Core Cmdlets for Reading:**
      * `Get-Item`: Gets details (list of properties) of the registry key.
      * `Get-ChildItem`: Lists sub-keys of a key (use the `-Recurse` parameter to list recursively).
      * `Get-ItemProperty`: Views values of registry keys.

### Editing the Registry

The following cmdlets are used to edit, create, or rename values and keys in the registry:

  * `Set-Item`
  * `Set-ItemProperty`
  * `New-Item`
  * `Rename-Item`
  * `New-ItemProperty`
  * `Rename-Itemproperty`

### Accessing Other Hives

To access other Registry hives (like `HKEY_USERS`), you can create new **`PSDrive`s**:

  * **Create a new drive:**
    ```powershell
    New-PSDrive -Name <nameofpsdrive> -PSProvider Registry -Root Registry::HKEY_USERS
    ```
  * **Change location:** By setting the location to the Registry root (`Set-Location Registry::`), you can use the core cmdlets to access the keys.

## The Help System ❓

PowerShell has a great built-in help system that can solve most problems you will encounter.

  * If you want to learn PowerShell, you **must learn to use its help system**.
  * The system supports **wildcard** searching.
  * Use **`Update-Help`** (in v3 and later) to update your help files.

### Help Commands

| Command | Purpose |
| :--- | :--- |
| `Get-Help <cmdlet name \| topic name>` | Shows a brief help about the cmdlet or topic and comes with various options and filters. |
| `Get-Help About_<topic>` | Used to get help for conceptual topics (e.g., `About_Variables`). |
| **Aliases** | `Get-Help`, `Help`, and `-?` can all be used to display help. |
