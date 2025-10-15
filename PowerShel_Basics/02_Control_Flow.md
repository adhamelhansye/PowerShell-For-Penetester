# Control Flow in PowerShell ⚙️

Control flow statements manage the order of execution in a script, allowing for complex and logical automation.

-----

### IF Condition

The **`if`** statement executes a block of code only if a specified condition is **true**.

```powershell
if ( condition ) {
    # Code Here
}
```

**Example: Check if a file exists**
The `Test-Path` cmdlet is frequently used by attackers to check for config files or existing payloads.

```powershell
$file = "C:\mydatafile.txt"
if (Test-Path $file) {
    Write-Host "The File Exists"
} else {
    Write-Host "File Not Found "
}
```

-----

### For Loop

The **`for`** loop executes a block of code a specific number of times, commonly used for iterating through **IP ranges**.

```powershell
# $i = 1 (Initializer); $i -le 5 (Condition); i++ (Iterator)
for ($i = 1; $i -le 5; i++) {
    Write-Host "For Loop iteration: $i" 
}
```

-----

### ForEach Loop

The **`foreach`** loop is ideal for iterating through collections (arrays, lists, etc.), often used to process **lists of credentials** or hostnames.

```powershell
$lists = @("Apple", "Manga" , "Banan") 
foreach ($list in $lists){
    Write-Host "I like $list"
}
```

-----

### While Loop

The **`while`** loop executes a block of code repeatedly as long as a condition remains **true**, perfect for implementing **listeners** or polling a C2 server.

```powershell
$i = 1
while ($i -le 5) {
    Write-Host "While Loop : $i"
$i++}
```

-----

### Do...While Loop

The **`do...while`** loop guarantees the code block executes **at least once** before checking the condition.

```powershell
$i = 1
do {
    Write-Host "Do... While Loop $i"
    $i++
} while ($i -le 5)
```
