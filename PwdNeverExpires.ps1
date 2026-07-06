<#
.SYNOPSIS
    Audits Active Directory for accounts with the "Password Never Expires" flag.

.DESCRIPTION
    Enumerates user and/or computer accounts whose userAccountControl has the
    DONT_EXPIRE_PASSWORD (65536) bit set, using only built-in
    System.DirectoryServices classes (no ActiveDirectory module required),
    and exports the results to a CSV file.

.PARAMETER DomainInput
    Domain name (e.g. example.com) or distinguished name (e.g. DC=example,DC=com).
    If omitted, the current domain is detected and offered as the default.

.PARAMETER Server
    Optional domain controller to query directly, as host or host:port
    (e.g. dc01.example.com or dc01.example.com:636).

.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\PwdNeverExpires_<domain>.csv

.PARAMETER IncludeUsers
    Query user accounts only.

.PARAMETER IncludeComputers
    Query computer accounts only.
    If neither switch is specified, both users and computers are queried.

.EXAMPLE
    .\PwdNeverExpires.ps1 -DomainInput example.com -IncludeUsers
#>
[CmdletBinding()]
param(
    [string]$DomainInput,
    [string]$Server,
    [string]$OutputPath,
    [switch]$IncludeUsers,
    [switch]$IncludeComputers
)

function Convert-DomainToSearchBase {
    param([string]$DomainOrDn)

    if ([string]::IsNullOrWhiteSpace($DomainOrDn)) {
        throw "Empty domain input."
    }

    $DomainOrDn = $DomainOrDn.Trim()

    # If already in DN format, leave it as is
    if ($DomainOrDn -match '(?i)\bDC=') {
        return $DomainOrDn
    }

    # "example.com.tr" becomes "DC=example,DC=com,DC=tr"
    $labels = $DomainOrDn -split '\.'
    if ($labels.Count -lt 2) {
        throw "Please enter a valid domain name (e.g., example.com or example.com.tr)."
    }
    return 'DC=' + (($labels) -join ',DC=')
}

if (-not $DomainInput) {
    try {
        $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        Write-Host "Enter domain name [Press enter for: $currentDomain]:" -NoNewline -ForegroundColor Yellow
        $userInput = Read-Host
        $DomainInput = if ([string]::IsNullOrWhiteSpace($userInput)) { $currentDomain } else { $userInput }
    } catch {
        Write-Error "Unable to get current domain, please enter domain name manually (e.g., example.com.tr)."
        exit 1
    }
}

# If OutputPath not provided, default to the current directory with the domain name
if (-not $OutputPath) {
    $safeDomain = $DomainInput -replace '[^a-zA-Z0-9]', '_'
    $OutputPath = Join-Path -Path (Get-Location) -ChildPath ("PwdNeverExpires_{0}.csv" -f $safeDomain)
}

try {
    $SearchBase = Convert-DomainToSearchBase -DomainOrDn $DomainInput
} catch {
    Write-Error $_.Exception.Message
    exit 1
}

if ([string]::IsNullOrWhiteSpace($SearchBase)) {
    Write-Error "SearchBase was generated empty. Input: '$DomainInput'"
    exit 1
}

# Optional explicit DC: LDAP://dc01.example.com/DC=example,DC=com
$LdapPrefix = if ($Server) { "LDAP://$Server/" } else { "LDAP://" }

Write-Host "`nSelected domain: $DomainInput" -ForegroundColor Cyan
if ($Server) { Write-Host "Target server:   $Server" -ForegroundColor Cyan }
Write-Host "LDAP SearchBase: $SearchBase" -ForegroundColor Cyan
Write-Host "Output CSV Path: $OutputPath`n" -ForegroundColor Cyan

# --- Filters ---
$FilterUsers     = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
$FilterComputers = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
$Props = @("name","distinguishedName","whenCreated","lastLogonTimestamp","lastLogon","pwdLastSet","userAccountControl")

$Invariant = [System.Globalization.CultureInfo]::InvariantCulture
$AssumeUTC = [System.Globalization.DateTimeStyles]::AssumeUniversal

function Convert-FileTimeUtc {
    param([object]$val)
    if ($null -eq $val) { return $null }
    $n = 0L
    if (-not [Int64]::TryParse([string]$val, [ref]$n)) { return $null }
    if ($n -le 0) { return $null }
    try { [DateTime]::FromFileTimeUtc($n) } catch { $null }
}

function Convert-DateTimeSafe {
    param([object]$val)
    if ($null -eq $val) { return $null }
    if ($val -is [DateTime]) { return $val }
    try { return [Convert]::ToDateTime($val, $Invariant) } catch {}
    $fmts = @(
        "yyyyMMddHHmmss.0Z","yyyyMMddHHmmss'Z'",
        "yyyy-MM-ddTHH:mm:ss.fffZ","yyyy-MM-ddTHH:mm:ssZ",
        "yyyy-MM-dd HH:mm:ss","dd.MM.yyyy HH:mm:ss","M/d/yyyy h:mm:ss tt"
    )
    $out = [datetime]::MinValue
    foreach ($f in $fmts) {
        try {
            if ([datetime]::TryParseExact([string]$val, $f, $Invariant, $AssumeUTC, [ref]$out)) {
                return $out.ToUniversalTime()
            }
        } catch {}
    }
    return $null
}

function Format-DateUtc {
    # Culture-independent, sortable timestamp for the CSV
    param([object]$dt)
    if ($null -eq $dt) { return $null }
    return $dt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
}

function Get-NeverExpireObjects {
    param([string]$BaseDn,[string]$Filter,[string[]]$Props,[string]$ObjectType)

    $root = New-Object System.DirectoryServices.DirectoryEntry("$LdapPrefix$BaseDn")
    $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
    $ds.Filter = $Filter
    $ds.PageSize = 1000
    foreach ($pr in $Props) { [void]$ds.PropertiesToLoad.Add($pr) }

    $results = $null
    try {
        try {
            $results = $ds.FindAll()
        } catch {
            throw "LDAP query error: $($_.Exception.Message). BaseDN: '$BaseDn'. Possible solutions:
        1) Verify the domain and SearchBase are correct.
        2) Ensure the executing account has read permissions in Active Directory.
        3) Check network connectivity and firewall settings.
        4) Confirm the LDAP filter syntax is correct."
        }

        $total = $results.Count
        $counter = 0

        foreach ($res in $results) {
            $counter++
            Write-Progress -Activity "Processing $ObjectType objects..." -Status "Object $counter of $total" -PercentComplete (($counter / $total) * 100)

            # All requested attributes are already in the search result;
            # no extra per-object LDAP bind is needed.
            $p = $res.Properties
            $name = if ($p.name.Count) { $p.name[0] } else { $null }
            $dn   = if ($p.distinguishedname.Count) { $p.distinguishedname[0] } else { $null }

            $creation = if ($p.whencreated.Count) { Convert-DateTimeSafe $p.whencreated[0] } else { $null }

            $llt = $null
            if ($p.lastlogontimestamp.Count) { $llt = Convert-FileTimeUtc $p.lastlogontimestamp[0] }
            if (-not $llt -and $p.lastlogon.Count) { $llt = Convert-FileTimeUtc $p.lastlogon[0] }

            $pls = if ($p.pwdlastset.Count) { Convert-FileTimeUtc $p.pwdlastset[0] } else { $null }

            $enabled = $null
            if ($p.useraccountcontrol.Count) {
                # ACCOUNTDISABLE = 0x2
                $enabled = -not ([int]$p.useraccountcontrol[0] -band 2)
            }

            [pscustomobject]@{
                Name              = $name
                Type              = $ObjectType
                Enabled           = $enabled
                Creation          = Format-DateUtc $creation
                LastLogon         = Format-DateUtc $llt
                PwdLastSet        = Format-DateUtc $pls
                DistinguishedName = $dn
            }
        }
        Write-Progress -Activity "Processing $ObjectType objects..." -Completed
    } finally {
        if ($results) { $results.Dispose() }
        $ds.Dispose()
        $root.Dispose()
    }
}

# --- EXECUTION ---
$queryUsers     = $IncludeUsers -or (-not $IncludeUsers -and -not $IncludeComputers)
$queryComputers = $IncludeComputers -or (-not $IncludeUsers -and -not $IncludeComputers)

if ($queryUsers -and $queryComputers) {
    Write-Host "No scope specified, querying both users and computers..." -ForegroundColor Cyan
}

$all = @()

try {
    if ($queryUsers) {
        Write-Host "Querying users..." -ForegroundColor Cyan
        $all += Get-NeverExpireObjects -BaseDn $SearchBase -Filter $FilterUsers -Props $Props -ObjectType 'User'
    }

    if ($queryComputers) {
        Write-Host "Querying computers..." -ForegroundColor Cyan
        $all += Get-NeverExpireObjects -BaseDn $SearchBase -Filter $FilterComputers -Props $Props -ObjectType 'Computer'
    }
} catch {
    Write-Error $_.Exception.Message
    exit 1
}

$all = @($all | Sort-Object Type, Name)

if ($all.Count -eq 0) {
    Write-Host "`nNo accounts with 'Password Never Expires' were found." -ForegroundColor Green
    exit 0
}

$all | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# --- Summary ---
$userCount       = @($all | Where-Object { $_.Type -eq 'User' }).Count
$computerCount   = @($all | Where-Object { $_.Type -eq 'Computer' }).Count
$disabledCount   = @($all | Where-Object { $_.Enabled -eq $false }).Count
$emptyLastLogon  = @($all | Where-Object { -not $_.LastLogon }).Count
$emptyPwdLastSet = @($all | Where-Object { -not $_.PwdLastSet }).Count

Write-Host "`nCSV created: $OutputPath" -ForegroundColor Green
Write-Host "Total objects: $($all.Count) (Users: $userCount, Computers: $computerCount)" -ForegroundColor Magenta
Write-Host "Disabled accounts: $disabledCount" -ForegroundColor Magenta
Write-Host "No recorded logon: $emptyLastLogon" -ForegroundColor Magenta
Write-Host "No password-set date: $emptyPwdLastSet" -ForegroundColor Magenta
