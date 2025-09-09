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
---

##  Key Features
-  Detects all AD accounts (users and computers) with **non-expiring passwords**  
-  Works **without the Active Directory PowerShell module** 
-  Uses only built-in **.NET System.DirectoryServices** classes 
-  Compatible with **any Windows environment** with domain connectivity  
-  Exports results to a CSV file with attributes:
   - Name  
   - Creation Date  
   - Last Logon  
   - Last Password Set  
   - Distinguished Name  
-  Can run **without admin privileges**, only read access to AD is required  

---

## Why This Matters

Accounts with **"Password Never Expires"** pose a significant security risk:  

- If compromised, an attacker can **maintain access indefinitely**, because the password never expires.  
- Especially dangerous for **administrative or critical service accounts**, allowing long-term persistence.  
- Attackers can **move laterally, exfiltrate data, or manipulate systems** without being locked out.  

Regularly reviewing and remediating accounts with non-expiring passwords is essential to **reduce persistent threat risks**.

---

##  Why This Script Is Unique
Unlike most tools on GitHub:  
- Other tools require **Active Directory Module** (e.g., `Get-ADUser`, `Get-ADComputer`).  
- **This script has zero dependencies**:  
  - ✅ Runs on any Windows system  
  - ✅ No extra AD modules required  
  - ✅ **No admin privileges needed**; only read access to AD  
  - ✅ Usable in **restricted customer environments**  

---


## How It Works
1. **Domain Detection**: Automatically detects current domain or accepts manual input
2. **LDAP Query Construction**: Builds optimized LDAP filters for password never expires accounts
3. **Data Collection**: Retrieves account properties including:
   - **Name and Distinguished Name**
   - **Creation timestamp**
   - **Last logon information**
   - **Password last set date**
4. **Date Processing**: Converts various date formats (FileTime, GeneralizedTime) to readable format
5. **CSV Export**: Generates detailed reports with proper encoding


**Note**: If neither `-IncludeUsers` nor `-IncludeComputers` is specified, both are included by default.

## Usage

### Interactive Mode 
**Prompts for domain selection and includes all account types**
```powershell
.\PasswordNeverExpires.ps1
```


### Specific Domain Analysis
```powershell
.\PasswordNeverExpires.ps1 -DomainInput "example.com"
```
### Users Only

```powershell
.\PasswordNeverExpires.ps1 -IncludeUsers -OutputPath "C:\Audit\UsersNeverExpire.csv"
```
### Computers Only

```powershell
.\PasswordNeverExpires.ps1 -IncludeComputers -DomainInput "subsidiary.company.com"
```

### Cross-Domain Analysis
```powershell
.\PasswordNeverExpiresAnalyzer.ps1 -DomainInput "DC=remote,DC=domain,DC=com" -IncludeUsers
```
## Example Output

| Name | Creation | LastLogon | PwdLastSet | DistinguishedName |
|------|----------|-----------|------------|-------------------|
| ServiceAccount | 2020-01-15 08:30:00 | 2025-01-20 14:22:15 | 2020-01-15 08:30:00 | CN=ServiceAccount,OU=Service_Accounts,DC=company,DC=com |
| LegacyApp | 2018-05-10 12:00:00 | | 2018-05-10 12:00:00 | CN=LegacyApp,OU=Applications,DC=company,DC=com |
| AdminUser | 2019-03-20 09:15:30 | 2025-01-25 11:45:22 | 2019-03-20 09:15:30 | CN=AdminUser,OU=Administrators,DC=company,DC=com |
| TestComputer$ | 2021-07-08 16:20:00 | 2024-12-15 10:30:45 | 2021-07-08 16:20:00 | CN=TestComputer,OU=Workstations,DC=company,DC=com |



## Requirements & Notes
- **PowerShell 5.1 or higher** (uses .NET DirectoryServices classes)
- **Domain-joined machine** or network connectivity to target domain
- **Read permissions** on Active Directory (typically Domain Users sufficient)
- **LDAP connectivity** on port 389 (or 636 for LDAPS)


---

## Security Implications

### Why Password Never Expires is Dangerous
Accounts with **Password Never Expires** flag represent significant security risks:
- **Static credentials** that may be discovered through various attack vectors
- **Privilege escalation opportunities** if service accounts have elevated permissions
- **Persistence mechanisms** for attackers who compromise these accounts
- **Compliance violations** in environments with password rotation requirements

### Common Attack Scenarios
Attackers targeting password never expires accounts typically follow these patterns:
1. **Service Account Compromise**: Target service accounts with never-expiring passwords through credential stuffing or password spraying
2. **Dormant Account Exploitation**: Discover abandoned accounts that become backdoors into the environment
3. **Lateral Movement**: Use compromised never-expire accounts to traverse network segments
4. **Persistence Establishment**: Maintain long-term access through accounts that won't require password changes

This creates a **persistent attack surface** that remains stable for extended periods.

### Mitigation & Best Practices
- **Regular password rotation** for all service accounts (use Group Managed Service Accounts where possible)
- **Account lifecycle management** to identify and disable dormant accounts:
```powershell
$StaleAccounts = $Results | Where-Object {
$.LastLogon -lt (Get-Date).AddDays(-90) -or $null -eq $.LastLogon
}
```
- **Privilege review** to ensure accounts have minimum required permissions
- **Monitoring implementation** for unusual logon patterns from these accounts:
- Set up alerts for logons from never-expire accounts outside business hours
- Monitor for multiple failed logon attempts on service accounts
- Track privilege escalation attempts from these accounts
- **Compliance alignment** with organizational password policies
- **Group Managed Service Accounts (gMSA)** implementation where possible to eliminate static passwords entirely
