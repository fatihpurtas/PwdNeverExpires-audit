# Password Never Expires Analyzer

This PowerShell script enumerates all **Active Directory user and computer accounts** with the
**"Password Never Expires"** flag enabled and exports the results to a CSV file.

---

## Purpose
The **Password Never Expires** flag in Active Directory presents a significant security risk as these accounts:
- Never require password changes, potentially using weak or compromised passwords indefinitely
- May represent forgotten service accounts, abandoned user accounts, or misconfigured systems
- Can serve as persistence mechanisms for attackers who compromise them
- Often have elevated privileges but lack proper monitoring

Regularly reviewing and remediating accounts with non-expiring passwords is essential to reduce persistent threat risks.

---

## Key Features
- Detects all AD accounts (users and computers) with **non-expiring passwords**
- Works **without the Active Directory PowerShell module**. It uses only built-in **System.DirectoryServices** classes, so it runs in restricted environments where extra modules cannot be installed
- Can run **without admin privileges**; only read access to AD is required
- Can target a **specific domain controller** with the `-Server` parameter
- Paged LDAP queries (1000 objects per page), suitable for large domains
- Exports results to CSV with:
  - Name
  - Type (User / Computer)
  - Enabled (account enabled or disabled)
  - Creation date
  - Last logon
  - Password last set
  - Distinguished Name
- All timestamps in the CSV are written in **UTC** using a sortable `yyyy-MM-dd HH:mm:ss` format
- Prints a summary after export (totals, disabled accounts, accounts with no recorded logon or password-set date)

---

## How It Works
1. **Domain Detection**: Automatically detects the current domain or accepts manual input (domain name or DN)
2. **LDAP Query Construction**: Builds LDAP filters matching the `DONT_EXPIRE_PASSWORD` (65536) bit in `userAccountControl`
3. **Data Collection**: Retrieves name, DN, creation timestamp, last logon, password-last-set and account status in a single paged search, with no per-object round trips
4. **Date Processing**: Converts FileTime and GeneralizedTime values to readable UTC timestamps
5. **CSV Export**: Generates the report with UTF-8 encoding

**Note**: If neither `-IncludeUsers` nor `-IncludeComputers` is specified, both are included by default.

---

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-DomainInput` | Domain name (`example.com`) or distinguished name (`DC=example,DC=com`). Prompts with the current domain as default when omitted. |
| `-Server` | Optional domain controller to query directly (`dc01.example.com` or `dc01.example.com:636`). |
| `-OutputPath` | CSV output path. Defaults to `.\PwdNeverExpires_<domain>.csv`. |
| `-IncludeUsers` | Query user accounts only. |
| `-IncludeComputers` | Query computer accounts only. |

---

## Usage

### Interactive Mode
Prompts for domain selection and includes all account types:
```powershell
.\PwdNeverExpires.ps1
```

### Specific Domain Analysis
```powershell
.\PwdNeverExpires.ps1 -DomainInput "example.com"
```

### Users Only
```powershell
.\PwdNeverExpires.ps1 -IncludeUsers -OutputPath "C:\Audit\UsersNeverExpire.csv"
```

### Computers Only
```powershell
.\PwdNeverExpires.ps1 -IncludeComputers -DomainInput "subsidiary.company.com"
```

### Cross-Domain Analysis
```powershell
.\PwdNeverExpires.ps1 -DomainInput "DC=remote,DC=domain,DC=com" -IncludeUsers
```

### Query a Specific Domain Controller
```powershell
.\PwdNeverExpires.ps1 -DomainInput "example.com" -Server "dc01.example.com"
```

---

## Example Output

| Name | Type | Enabled | Creation | LastLogon | PwdLastSet | DistinguishedName |
|------|------|---------|----------|-----------|------------|-------------------|
| ServiceAccount | User | True | 2020-01-15 08:30:00 | 2025-01-20 14:22:15 | 2020-01-15 08:30:00 | CN=ServiceAccount,OU=Service_Accounts,DC=company,DC=com |
| LegacyApp | User | False | 2018-05-10 12:00:00 | | 2018-05-10 12:00:00 | CN=LegacyApp,OU=Applications,DC=company,DC=com |
| AdminUser | User | True | 2019-03-20 09:15:30 | 2025-01-25 11:45:22 | 2019-03-20 09:15:30 | CN=AdminUser,OU=Administrators,DC=company,DC=com |
| TestComputer$ | Computer | True | 2021-07-08 16:20:00 | 2024-12-15 10:30:45 | 2021-07-08 16:20:00 | CN=TestComputer,OU=Workstations,DC=company,DC=com |

---

## Requirements & Notes
- **PowerShell 5.1 or higher** (uses .NET DirectoryServices classes)
- **Domain-joined machine** or network connectivity to the target domain
- **Read permissions** on Active Directory (typically Domain Users is sufficient)
- **LDAP connectivity** on port 389 (or 636 for LDAPS)
- `lastLogon` is not replicated between domain controllers; `lastLogonTimestamp` (used first) is replicated but may lag up to 14 days behind the actual last logon

---

## Security Implications

### Common Attack Scenarios
Attackers targeting password-never-expires accounts typically follow these patterns:
1. **Service Account Compromise**: Target service accounts with never-expiring passwords through credential stuffing or password spraying
2. **Dormant Account Exploitation**: Discover abandoned accounts that become backdoors into the environment
3. **Lateral Movement**: Use compromised never-expire accounts to traverse network segments
4. **Persistence Establishment**: Maintain long-term access through accounts that won't require password changes

This creates a **persistent attack surface** that remains stable for extended periods.

### Mitigation & Best Practices
- **Regular password rotation** for all service accounts (use Group Managed Service Accounts where possible)
- **Account lifecycle management** to identify and disable dormant accounts:
```powershell
$Results = Import-Csv .\PwdNeverExpires_example_com.csv
$StaleAccounts = $Results | Where-Object {
    -not $_.LastLogon -or [datetime]$_.LastLogon -lt (Get-Date).AddDays(-90)
}
```
- **Privilege review** to ensure accounts have minimum required permissions
- **Monitoring implementation** for unusual logon patterns from these accounts:
  - Set up alerts for logons from never-expire accounts outside business hours
  - Monitor for multiple failed logon attempts on service accounts
  - Track privilege escalation attempts from these accounts
- **Compliance alignment** with organizational password policies
- **Group Managed Service Accounts (gMSA)** implementation where possible to eliminate static passwords entirely
