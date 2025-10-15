**Script/Command:**

```powershell
$command = $connection.CreateCommand()
$command.CommandText = "SELECT user, host FROM mysql.user;"
$users = $command.ExecuteReader()
while ($users.Read()) {
    Write-Host "User: $($users["user"])@($users["host"])"
}
$users.Close()
```

**Description:**

Queries the MySQL `mysql.user` table to retrieve a list of users and their associated hosts for access control verification.

**Example:**

List all MySQL users to check for unauthorized accounts.

---

**Script/Command:**

```powershell
$command.CommandText = "SHOW GRANTS FOR 'myuser'@'localhost';"
$privileges = $command.ExecuteReader()
while ($privileges.Read()) {
    Write-Host "Privilege: $($privileges[0])"
}
```

**Description:**

Verifies the privileges assigned to a specific MySQL user by querying the grants for the specified user.

**Example:**

Check privileges for 'myuser'@'localhost' to ensure least privilege enforcement.

---

**Script/Command:**

```powershell
$command.CommandText = "SHOW VARIABLES LIKE 'validate_password%';"
$passwordPolicy = $command.ExecuteReader()
while ($passwordPolicy.Read()) {
    Write-Host "Setting: $($passwordPolicy["Variable_name"]), Value: $($passwordPolicy["Value"])"
}
```

**Description:**

Assesses MySQL password policy settings to ensure compliance with security best practices.

**Example:**

Review password complexity and enforcement settings.

---

**Script/Command:**

```powershell
$command.CommandText = "SHOW VARIABLES LIKE 'have_ssl';"
$sslEnabled = $command.ExecuteScalar()
Write-Host "SSL/TLS Enabled: $sslEnabled"
```

**Description:**

Evaluates the SSL/TLS configuration to confirm data in transit is protected in MySQL.

**Example:**

Check if SSL/TLS is enabled for secure connections.

---

**Script/Command:**

```powershell
$command.CommandText = "SHOW VARIABLES LIKE 'innodb_encrypt%' OR 'encrypt%';"
$encryptionSettings = $command.ExecuteReader()
while ($encryptionSettings.Read()) {
    Write-Host "Setting: $($encryptionSettings["Variable_name"]), Value: $($encryptionSettings["Value"])"
}
```

**Description:**

Checks MySQL encryption settings for data at rest and in transit to assess data protection levels.

**Example:**

Verify if InnoDB encryption or other encryption features are enabled.

---

**Script/Command:**

```powershell
$command.CommandText = "SHOW VARIABLES LIKE 'secure_file_priv';"
$backupSecurity = $command.ExecuteScalar()
Write-Host "Backup Security: $backupSecurity"
```

**Description:**

Reviews MySQL backup security configurations to ensure proper restrictions on file privileges.

**Example:**

Check the directory where secure file operations are allowed.

---

**Script/Command:**

```powershell
$command.CommandText = "SHOW VARIABLES LIKE 'log_error';"
$errorLogPath = $command.ExecuteScalar()
$logs = Get-Content $errorLogPath
Write-Host "Contents of MySQL Error Log:"
Write-Host $logs
```

**Description:**

Retrieves and reviews MySQL error logs to detect security-related issues.

**Example:**

Analyze logs for errors indicating potential vulnerabilities.

---

**Script/Command:**

```powershell
Import-Module Npgsql
$server = "your_postgresql_server"
$database = "your_database"
$username = "your_username"
$password = "your_password"
$connectionString = "Server=$server;Database=$database;User Id=$username;Password=$password;"
$query = "SELECT username FROM pg_user;"
$connection = New-Object Npgsql.NpgsqlConnection
$connection.ConnectionString = $connectionString
$connection.Open()
$command = $connection.CreateCommand()
$command.CommandText = $query
$users = $command.ExecuteReader()
while ($users.Read()) {
    Write-Host "User: $($users["username"])"
}
$connection.Close()
```

**Description:**

Lists PostgreSQL users by querying the `pg_user` table for access control verification.

**Example:**

Identify all users with access to the PostgreSQL database.

---

**Script/Command:**

```powershell
Import-Module Npgsql
$server = "postgresql.snowcapcyber.com"
$port = 5432
$database = "mypostdb"
$username = "mypostuser"
$password = "mypostpassword"
$connectionString = "Host=$server;Port=$port;Database=$database;Username=$username;Password=$password;"
$connection = Connect-Npgsql -ConnectionString $connectionString
if ($connection.State -eq 'Open') {
    $privilegesQuery = "SELECT grantee, privilege_type, table_name FROM information_schema.role_table_grants WHERE grantee = '$username';"
    $command = $connection.CreateCommand()
    $command.CommandText = $privilegesQuery
    $privileges = $command.ExecuteReader()
    if ($privileges.HasRows) {
        Write-Host "User Privileges for $username in $database:"
        while ($privileges.Read()) {
            $grantee = $privileges['grantee']
            $privilegeType = $privileges['privilege_type']
            $tableName = $privileges['table_name']
            Write-Host "  Grantee: $grantee, Privilege Type: $privilegeType, Table Name: $tableName"
        }
    } else {
        Write-Host "No privileges found for user $username in $database."
    }
    $connection.Close()
}
```

**Description:**

Checks user privileges in PostgreSQL by querying `information_schema.role_table_grants`.

**Example:**

Verify privileges for 'mypostuser' to ensure proper access controls.

---

**Script/Command:**

```powershell
Import-Module Npgsql
$server = "postgresql.snowcapcyber.com"
$port = 5432
$database = "mypostdb"
$username = "mypostuser"
$password = "mypostpassword"
$connectionString = "Host=$server;Port=$port;Database=$database;Username=$username;Password=$password;"
$connection = Connect-Npgsql -ConnectionString $connectionString
if ($connection.State -eq 'Open') {
    $passwordSettingsQuery = "SELECT name AS 'Parameter', setting AS 'Value' FROM pg_settings WHERE name IN ('password_encryption', 'password_check_duration', 'password_min_length');"
    $command = $connection.CreateCommand()
    $command.CommandText = $passwordSettingsQuery
    $passwordSettings = $command.ExecuteReader()
    if ($passwordSettings.HasRows) {
        Write-Host "Password Policy Settings in PostgreSQL for $database:"
        while ($passwordSettings.Read()) {
            $parameter = $passwordSettings['Parameter']
            $value = $passwordSettings['Value']
            Write-Host "  $parameter: $value"
        }
    } else {
        Write-Host "No password policy settings found in PostgreSQL for $database."
    }
    $connection.Close()
}
```

**Description:**

Assesses PostgreSQL password policy settings by querying `pg_settings`.

**Example:**

Review encryption and minimum length settings for passwords.

---

**Script/Command:**

```powershell
Import-Module Npgsql
$server = "postgresql.snowcapcyber.com"
$port = 5432
$database = "mypostdb"
$username = "mypostuser"
$password = "mypostpassword"
$connectionString = "Host=$server;Port=$port;Database=$database;Username=$username;Password=$password;"
$connection = Connect-Npgsql -ConnectionString $connectionString
if ($connection.State -eq 'Open') {
    $sslConfigQuery = "SELECT name AS 'Parameter', setting AS 'Value' FROM pg_settings WHERE name IN ('ssl', 'ssl_ca_file', 'ssl_cert_file', 'ssl_key_file', 'ssl_ciphers');"
    $command = $connection.CreateCommand()
    $command.CommandText = $sslConfigQuery
    $sslConfigSettings = $command.ExecuteReader()
    if ($sslConfigSettings.HasRows) {
        Write-Host "SSL/TLS Configuration in PostgreSQL for $database:"
        while ($sslConfigSetting = $sslConfigSettings.Read()) {
            $parameter = $sslConfigSetting['Parameter']
            $value = $sslConfigSetting['Value']
            Write-Host "  $parameter: $value"
        }
    } else {
        Write-Host "No SSL/TLS configuration settings found in PostgreSQL for $database."
    }
    $connection.Close()
}
```

**Description:**

Evaluates PostgreSQL SSL/TLS configuration by querying `pg_settings`.

**Example:**

Check if SSL/TLS is enabled and review certificate settings.

---

**Script/Command:**

```powershell
Import-Module Npgsql
$server = "postgresql.snowcapcyber.com"
$port = 5432
$database = "mypostdb"
$username = "mypostuser"
$password = "mypostpassword"
$connectionString = "Host=$server;Port=$port;Database=$database;Username=$username;Password=$password;"
$connection = Connect-Npgsql -ConnectionString $connectionString
if ($connection.State -eq 'Open') {
    $encryptionQuery = "SELECT name AS 'Parameter', setting AS 'Value' FROM pg_settings WHERE name IN ('ssl', 'ssl_ca_file', 'ssl_cert_file', 'ssl_key_file');"
    $command = $connection.CreateCommand()
    $command.CommandText = $encryptionQuery
    $encryptionSettings = $command.ExecuteReader()
    if ($encryptionSettings.HasRows) {
        Write-Host "Encryption Settings in PostgreSQL for $database:"
        while ($encryptionSetting = $encryptionSettings.Read()) {
            $parameter = $encryptionSetting['Parameter']
            $value = $encryptionSetting['Value']
            Write-Host "  $parameter: $value"
        }
    } else {
        Write-Host "No encryption settings found in PostgreSQL for $database."
    }
    $connection.Close()
}
```

**Description:**

Assesses PostgreSQL data encryption settings, focusing on SSL-related parameters.

**Example:**

Verify encryption configurations for data in transit.

---

**Script/Command:**

```powershell
$backupDirectory = "C:\path\to\backup\directory"
$backupFiles = Get-ChildItem -Path $backupDirectory
if ($backupFiles.Count -gt 0) {
    Write-Host "PostgreSQL Backup Files in $backupDirectory:"
    foreach ($backupFile in $backupFiles) {
        $backupFilePath = $backupFile.FullName
        Write-Host "Backup file: $($backupFile.Name)"
        $fileSecurity = Get-Acl -Path $backupFilePath
        Write-Host "Security settings:"
        foreach ($ace in $fileSecurity.Access) {
            Write-Host "  User/Group: $($ace.IdentityReference), Permissions: $($ace.FileSystemRights)"
        }
        Write-Host ""
    }
} else {
    Write-Host "No PostgreSQL backup files found in the specified directory."
}
```

**Description:**

Reviews PostgreSQL backup file security by checking permissions and access controls.

**Example:**

Audit backup directory permissions for unauthorized access.

---

**Script/Command:**

```powershell
$logDirectory = "C:\PostgreSQL\13\data\pg_log"
$logFiles = Get-ChildItem -Path $logDirectory -Filter "postgresql*.log"
if ($logFiles.Count -gt 0) {
    Write-Host "PostgreSQL Error Logs:"
    foreach ($logFile in $logFiles) {
        $logFilePath = $logFile.FullName
        $logLines = Get-Content -Path $logFilePath
        Write-Host "Log file: $($logFile.Name)"
        $errorEntries = $logLines | Where-Object { $_ -match "ERROR|FATAL|PANIC" }
        if ($errorEntries.Count -gt 0) {
            Write-Host "Errors found:"
            foreach ($errorEntry in $errorEntries) {
                Write-Host "  $errorEntry"
            }
        } else {
            Write-Host "No errors found in this log file."
        }
        Write-Host ""
    }
} else {
    Write-Host "No PostgreSQL log files found in the specified directory."
}
```

**Description:**

Reviews PostgreSQL error logs to detect security-related issues by filtering for error messages.

**Example:**

Analyze logs for potential security incidents.

---

**Script/Command:**

```powershell
Import-Module SqlServer
$serverInstance = "localhost"
$database = "YourDatabase"
$username = "YourUsername"
$password = "YourPassword"
$connectionString = "Server=$serverInstance;Database=$database;User Id=$username;Password=$password;"
$connection = New-Object System.Data.SqlClient.SqlConnection
$connection.ConnectionString = $connectionString
$connection.Open()
$command = $connection.CreateCommand()
$command.CommandText = "SELECT name, type_desc, is_disabled FROM sys.sql_logins;"
$logins = $command.ExecuteReader()
while ($logins.Read()) {
    Write-Host "Login: $($logins["name"]), Type: $($logins["type_desc"]), Disabled: $($logins["is_disabled"])"
}
$connection.Close()
```

**Description:**

Lists SQL Server logins and their properties (e.g., type, disabled status) for access control verification.

**Example:**

Identify all logins to check for disabled or unauthorized accounts.

---

**Script/Command:**

```powershell
$targetUsername = "JohnDoe"
$command = $connection.CreateCommand()
$command.CommandText = "EXEC sp_helprotect @username;"
$command.Parameters.AddWithValue("@username", $targetUsername)
$privileges = $command.ExecuteReader()
while ($privileges.Read()) {
    Write-Host "Object Name: $($privileges["Object_Name"]), Permission: $($privileges["Permission_Name"]), Grantor: $($privileges["Grantor"])"
}
```

**Description:**

Verifies privileges for a specific SQL Server user using the `sp_helprotect` stored procedure.

**Example:**

Check permissions for 'JohnDoe' to ensure least privilege.

---

**Script/Command:**

```powershell
$command = $connection.CreateCommand()
$command.CommandText = "SELECT * FROM sys.sql_logins WHERE is_policy_checked = 1;"
$passwordPolicies = $command.ExecuteReader()
while ($passwordPolicies.Read()) {
    Write-Host "Login: $($passwordPolicies["name"]), Password Policy Enforced: $($passwordPolicies["is_policy_checked"])"
}
```

**Description:**

Assesses SQL Server password policy enforcement for logins.

**Example:**

Verify which logins have password policies enabled.

---

**Script/Command:**

```powershell
$command = $connection.CreateCommand()
$command.CommandText = "SELECT name, protocol_desc, local_net_address, local_tcp_port, type_desc, role_desc FROM sys.dm_exec_connections;"
$connections = $command.ExecuteReader()
while ($connections.Read()) {
    Write-Host "Name: $($connections["name"]), Protocol: $($connections["protocol_desc"]), Local Address: $($connections["local_net_address"]), Local Port: $($connections["local_tcp_port"]), Type: $($connections["type_desc"]), Role: $($connections["role_desc"])"
}
```

**Description:**

Evaluates SQL Server SSL/TLS and encryption settings by querying active connections.

**Example:**

Check if connections use secure protocols.

---

**Script/Command:**

```powershell
$command = $connection.CreateCommand()
$command.CommandText = "SELECT name, is_encryption_enabled, encryption_type_desc FROM sys.dm_database_encryption_keys;"
$encryptionKeys = $command.ExecuteReader()
while ($encryptionKeys.Read()) {
    Write-Host "Database: $($encryptionKeys["name"]), Encryption Enabled: $($encryptionKeys["is_encryption_enabled"]), Encryption Type: $($encryptionKeys["encryption_type_desc"])"
}
```

**Description:**

Checks SQL Server data encryption status using `sys.dm_database_encryption_keys`.

**Example:**

Verify if Transparent Data Encryption (TDE) is enabled.

---

**Script/Command:**

```powershell
$command = $connection.CreateCommand()
$command.CommandText = "EXEC sp_MSforeachdb 'USE [?]; SELECT name, recovery_model_desc, is_broker_enabled FROM sys.databases;'"
$databases = $command.ExecuteReader()
while ($databases.Read()) {
    Write-Host "Database: $($databases["name"]), Recovery Model: $($databases["recovery_model_desc"]), Service Broker Enabled: $($databases["is_broker_enabled"])"
}
```

**Description:**

Assesses SQL Server backup security by reviewing database recovery models and configurations.

**Example:**

Check recovery models to ensure backup integrity.

---

**Script/Command:**

```powershell
$command = $connection.CreateCommand()
$command.CommandText = "EXEC xp_readerrorlog;"
$errorLogs = $command.ExecuteReader()
while ($errorLogs.Read()) {
    Write-Host "Log Date: $($errorLogs["LogDate"]), Process Info: $($errorLogs["ProcessInfo"]), Message: $($errorLogs["Text"])"
}
```

**Description:**

Reviews SQL Server error logs for security-related issues.

**Example:**

Analyze logs for signs of unauthorized access.

---

**Script/Command:**

```powershell
$command = $connection.CreateCommand()
$command.CommandText = "SELECT * FROM sys.fn_get_audit_file('C:\Audit\*.sqlaudit', DEFAULT, DEFAULT);"
$auditLogs = $command.ExecuteReader()
while ($auditLogs.Read()) {
    Write-Host "Event Time: $($auditLogs["event_time"]), Action: $($auditLogs["action_id"]), Object Name: $($auditLogs["object_name"])"
}
```

**Description:**

Monitors SQL Server audit logs to track and analyze security events.

**Example:**

Review audit logs for suspicious activities.

---
