param(
    [string]$DomainInput,
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

    # "example.com.tr" → "DC=example,DC=com,DC=tr"
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

# If OutputPath not provided → default to current directory with domain name
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

Write-Host "`nSelected domain: $DomainInput" -ForegroundColor Cyan
Write-Host "LDAP SearchBase: $SearchBase`n" -ForegroundColor Cyan
Write-Host "Output CSV Path: $OutputPath`n" -ForegroundColor Cyan

# --- Filters ---
$FilterUsers     = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
$FilterComputers = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
$Props = @("name","distinguishedName","adspath","whenCreated","lastLogonTimestamp","lastLogon","pwdLastSet")

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

function Get-NeverExpireObjects {
    param([string]$BaseDn,[string]$Filter,[string[]]$Props)

    $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$BaseDn")
    $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
    $ds.Filter = $Filter
    $ds.PageSize = 1000
    foreach ($pr in $Props) { [void]$ds.PropertiesToLoad.Add($pr) }

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

    foreach($res in $results){
        $counter++
        Write-Progress -Activity "Processing LDAP results..." -Status "Object $counter of $total" -PercentComplete (($counter / $total) * 100)

        $p = $res.Properties
        $name = if ($p.name.Count) { $p.name[0] } else { $null }
        $dn   = if ($p.distinguishedname.Count) { $p.distinguishedname[0] } else { $null }

        $de = $null
        try {
            $de = New-Object System.DirectoryServices.DirectoryEntry($res.Path)
            $de.RefreshCache(@("whenCreated","lastLogonTimestamp","lastLogon","pwdLastSet"))
        } catch {}

        $creation = $null
        if ($de) { try { $creation = Convert-DateTimeSafe $de.Properties["whenCreated"].Value } catch {} }
        if (-not $creation -and $p.whencreated.Count) { $creation = Convert-DateTimeSafe $p.whencreated[0] }

        $llt = $null
        if ($de) {
            $rawLLT = $de.Properties["lastLogonTimestamp"].Value
            $rawLL  = $de.Properties["lastLogon"].Value
            if ($rawLLT) { $llt = Convert-FileTimeUtc $rawLLT }
            if (-not $llt -and $rawLL) { $llt = Convert-FileTimeUtc $rawLL }
        }
        if (-not $llt) {
            if ($p.lastlogontimestamp.Count) { $llt = Convert-FileTimeUtc $p.lastlogontimestamp[0] }
            if (-not $llt -and $p.lastlogon.Count) { $llt = Convert-FileTimeUtc $p.lastlogon[0] }
        }

        $pls = $null
        if ($de) { $pls = Convert-FileTimeUtc $de.Properties["pwdLastSet"].Value }
        if (-not $pls -and $p.pwdlastset.Count) { $pls = Convert-FileTimeUtc $p.pwdlastset[0] }

        [pscustomobject]@{
            Name              = $name
            Creation          = $creation
            LastLogon         = $llt
            PwdLastSet        = $pls
            DistinguishedName = $dn
        }
    }
}

# --- EXECUTION ---
$all = @()

if ($IncludeUsers) {
    Write-Host "Querying users..." -ForegroundColor Cyan
    $all += Get-NeverExpireObjects -BaseDn $SearchBase -Filter $FilterUsers -Props $Props
}

if ($IncludeComputers) {
    Write-Host "Querying computers..." -ForegroundColor Cyan
    $all += Get-NeverExpireObjects -BaseDn $SearchBase -Filter $FilterComputers -Props $Props
}

if (-not $IncludeUsers -and -not $IncludeComputers) {
    Write-Host "By default, both users and computers are being queried..." -ForegroundColor Cyan
    $all += Get-NeverExpireObjects -BaseDn $SearchBase -Filter $FilterUsers -Props $Props
    $all += Get-NeverExpireObjects -BaseDn $SearchBase -Filter $FilterComputers -Props $Props
}

$all = $all | Sort-Object Name
$all | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "`nCSV created: $OutputPath" -ForegroundColor Green
$emptyLastLogon = ($all | Where-Object { -not $_.LastLogon }).Count
$emptyPwdLastSet = ($all | Where-Object { -not $_.PwdLastSet }).Count
Write-Host "Total objects: $($all.Count)" -ForegroundColor Magenta
