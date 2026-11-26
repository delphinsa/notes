<#
.SYNOPSIS
    Releve en LECTURE SEULE des composants Oracle Fusion Middleware (ODI,
    WebLogic, OPSS, OAM, OBIEE...) et des bases Oracle d'un serveur Windows.

.DESCRIPTION
    Check-OracleFMW.ps1 - v1.1 (26/11/2026)
    Contexte : CSPU Oracle de novembre 2026
      CVE-2026-91569  WebLogic Server (TopLink Integration)
      CVE-2026-114824 Oracle Platform Security for Java (Centralized Thirdparty Jars)
      CVE-2026-114835 / -91500 / -91510  Oracle Access Manager
      CVE-2026-114784 Oracle Business Intelligence Enterprise Edition
      CVE-2026-91558  Service Delivery Platform
    Cibles SIDV : Cybele-W2 (prod), Heracles-W2 (recette), Cybele-GX2 (controle).

    Le script ne modifie rien. Seule exception : OPatch ecrit ses propres logs
    dans <ORACLE_HOME>\cfgtoollogs\opatch (option -NoOPatch pour l'eviter).
    Les valeurs qui ressemblent a des mots de passe sont masquees.
    A lancer dans une console PowerShell en administrateur.

.PARAMETER ExpectedPatches
    Numeros de patch attendus (Patch Availability Document MOS du CSPU),
    compares a la liste des patchs de chaque Oracle Home Fusion Middleware.

.PARAMETER OutDir
    Dossier du rapport (defaut : dossier courant).

.PARAMETER NoOPatch
    Ne pas lancer OPatch (lecture des fichiers d'inventaire uniquement).

.PARAMETER NoDiskSearch
    Ne pas parcourir les disques (Oracle Homes deduits de l'inventaire,
    du registre et des process uniquement).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Check-OracleFMW.ps1

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Check-OracleFMW.ps1 -ExpectedPatches "12345678,23456789"
#>
[CmdletBinding()]
param(
    [string[]]$ExpectedPatches = @(),
    [string]$OutDir = (Get-Location).Path,
    [switch]$NoOPatch,
    [switch]$NoDiskSearch
)

$ErrorActionPreference = 'Continue'
$ScriptVersion = '1.1'
$HostName = $env:COMPUTERNAME
$Stamp = Get-Date -Format 'yyyyMMdd_HHmm'
$Report = Join-Path $OutDir ('oraclefmw_{0}_{1}.txt' -f $HostName, $Stamp)
$Expected = @($ExpectedPatches | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ -match '^\d+$' })

# Motif des process a detailler (ODI, WebLogic, FMW)
$FlagRe = '(?i)oracle\.odi|\\odi\\|odi64\.exe|\\odi\.exe|weblogic|wlserver|NodeManager|oracle_common|Oracle_Home|\\Middleware\\|oam_server|bi_server|obis'

# ---------------------------------------------------------------------------
# Etat global
# ---------------------------------------------------------------------------
$OHs        = New-Object System.Collections.Generic.List[string]
$Doms       = New-Object System.Collections.Generic.List[string]
$OpssHomes  = New-Object System.Collections.Generic.List[string]
$WlsHomes   = New-Object System.Collections.Generic.List[string]
$OdiHomes   = New-Object System.Collections.Generic.List[string]
$DbHomes    = New-Object System.Collections.Generic.List[string]
$OamWhere   = New-Object System.Collections.Generic.List[string]
$BiWhere    = New-Object System.Collections.Generic.List[string]
$SdpWhere   = New-Object System.Collections.Generic.List[string]
$JeeWhere   = New-Object System.Collections.Generic.List[string]
$ListenFlag = New-Object System.Collections.Generic.List[string]
$Missing    = New-Object System.Collections.Generic.List[string]
$FlagPids   = @{}
$St = @{ WlsRunning = $false; NmRunning = $false; OdiRunning = $false; DbFound = $false; DefaultJH = '' }

# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------
function Out-Rep {
    param([AllowEmptyString()][AllowNull()][string]$Text = '')
    if ($null -eq $Text) { $Text = '' }
    Write-Host $Text
    Add-Content -LiteralPath $Report -Value $Text -Encoding UTF8
}

function Out-RepObj {
    param($Obj)
    $t = ($Obj | Out-String -Width 400).TrimEnd()
    if ($t) { Out-Rep $t }
}

function Out-Section {
    param([string]$Title)
    Out-Rep ''
    Out-Rep ('=' * 78)
    Out-Rep $Title
    Out-Rep ('=' * 78)
}

function Hide-Secret {
    param([string]$Text)
    if (-not $Text) { return '' }
    return ($Text -replace '(?i)((pass|pwd|password|secret|credential|token)[\w.\-]*\s*[=:]\s*)[^\s,;"]+', '$1****')
}

function Get-XmlAttr {
    param([string]$Tag, [string]$Name)
    $m = [regex]::Match($Tag, '\s' + $Name + '="([^"]*)"')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function Get-JavaHomeFromPath {
    # Accepte ...\bin\java.exe, ...\bin\server\jvm.dll ou ...\jre\bin\...
    param([string]$p)
    if (-not $p) { return '' }
    $h = $p -replace '(?i)\\bin\\(server\\|client\\)?(jvm\.dll|javaw?\.exe)$', ''
    $h = $h -replace '(?i)\\jre$', ''
    return $h
}

function Add-OH {
    param([string]$Path, [string]$Source)
    if (-not $Path) { return }
    try { $p = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath.TrimEnd('\') } catch { return }
    if (-not (Test-Path -LiteralPath $p -PathType Container)) { return }
    foreach ($e in $OHs) {
        if ($e -ieq $p) { return }
        # v1.1 : un dossier situe a l'interieur d'un Oracle Home deja retenu n'est pas un Oracle Home
        if ($p.StartsWith($e + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return }
    }
    # v1.1 : si des candidats deja retenus sont a l'interieur de celui-ci, on les retire
    foreach ($e in @($OHs)) {
        if ($e.StartsWith($p + '\', [System.StringComparison]::OrdinalIgnoreCase)) { [void]$OHs.Remove($e) }
    }
    $OHs.Add($p)
    Out-Rep ('  -> Oracle Home candidat : {0}  (source : {1})' -f $p, $Source)
}

function Test-HomeShape {
    # v1.1 : un vrai Oracle Home contient OPatch\opatch.bat ou inventory\ (evite cfgtoollogs\opatch, etc.)
    param([string]$Path)
    if (-not $Path) { return $false }
    try {
        if (Test-Path -LiteralPath (Join-Path (Join-Path $Path 'OPatch') 'opatch.bat')) { return $true }
        if (Test-Path -LiteralPath (Join-Path $Path 'inventory') -PathType Container) { return $true }
    } catch { }
    return $false
}

function Add-Dom {
    param([string]$Path, [string]$Source)
    if (-not $Path) { return }
    try { $p = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath.TrimEnd('\') } catch { return }
    if (-not (Test-Path -LiteralPath (Join-Path $p 'config\config.xml'))) { return }
    foreach ($e in $Doms) { if ($e -ieq $p) { return } }
    $Doms.Add($p)
    Out-Rep ('  -> Domaine candidat      : {0}  (source : {1})' -f $p, $Source)
}

function Get-Prop {
    param([string]$CmdLine, [string]$Name)
    $m = [regex]::Match($CmdLine, '-D' + [regex]::Escape($Name) + '=("([^"]*)"|(\S+))')
    if ($m.Success) { if ($m.Groups[2].Success) { return $m.Groups[2].Value } else { return $m.Groups[3].Value } }
    return ''
}

function Get-XmlChild {
    param($Node, [string]$Name)
    $n = $Node.SelectSingleNode("*[local-name()='$Name']")
    if ($n) { return $n.InnerText }
    return ''
}

function Show-Presence {
    param([string]$OH, [string]$Rel, [string]$Comment)
    $ok = Test-Path -LiteralPath (Join-Path $OH $Rel)
    if ($ok) { $tag = '[OUI]' } else { $tag = '[non]' }
    Out-Rep ('  {0} {1,-42} {2}' -f $tag, $Rel, $Comment)
    return $ok
}

# ---------------------------------------------------------------------------
# 0. Contexte
# ---------------------------------------------------------------------------
New-Item -ItemType File -Path $Report -Force | Out-Null
$isAdmin = $false
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue

Out-Section '0. CONTEXTE'
Out-Rep ('Script          : Check-OracleFMW.ps1 v{0} (lecture seule)' -f $ScriptVersion)
Out-Rep ('Machine         : {0}' -f $HostName)
Out-Rep ('Date            : {0}' -f (Get-Date -Format 'dd/MM/yyyy HH:mm:ss'))
Out-Rep ('Execute par     : {0}\{1} (administrateur : {2})' -f $env:USERDOMAIN, $env:USERNAME, $isAdmin)
if (-not $isAdmin) { Out-Rep 'ATTENTION       : console non administrateur : modules, proprietaires et ports des autres comptes partiellement visibles.' }
if ($os) { Out-Rep ('OS              : {0} ({1})' -f $os.Caption, $os.Version) }
Out-Rep ('PowerShell      : {0}' -f $PSVersionTable.PSVersion)
if ($Expected.Count -gt 0) { Out-Rep ('Patchs attendus : {0}' -f ($Expected -join ' ')) } else { Out-Rep 'Patchs attendus : non fournis' }

# ---------------------------------------------------------------------------
# 1. Process Java (y compris JVM chargees dans un autre executable)
# ---------------------------------------------------------------------------
Out-Section '1. PROCESS JAVA ET JVM CHARGEES (detail des process ODI / WebLogic / FMW)'

$jvmOf = @{}
foreach ($gp in (Get-Process -ErrorAction SilentlyContinue)) {
    try {
        $m = $gp.Modules | Where-Object { $_.ModuleName -ieq 'jvm.dll' } | Select-Object -First 1
        if ($m) { $jvmOf[[int]$gp.Id] = $m.FileName }
    } catch { }
}
$wmi = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
$procName = @{}
foreach ($p in $wmi) { $procName[[int]$p.ProcessId] = $p.Name }

$javaProcs = @($wmi | Where-Object { $_.Name -match '^(?i)(java|javaw)\.exe$' -or $jvmOf.ContainsKey([int]$_.ProcessId) })
$rows = foreach ($p in $javaProcs) {
    $pidv = [int]$p.ProcessId
    $txt = '{0} {1} {2}' -f $p.ExecutablePath, $p.CommandLine, $jvmOf[$pidv]
    $flag = '-'
    if ($txt -match $FlagRe) { $flag = 'OUI'; $FlagPids[$pidv] = $true }
    $owner = ''
    try {
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
        if ($o.User) { $owner = '{0}\{1}' -f $o.Domain, $o.User }
    } catch { }
    [pscustomobject]@{ PID = $pidv; Process = $p.Name; Compte = $owner; 'ODI/FMW' = $flag; JVM = $jvmOf[$pidv] }
}
if ($javaProcs.Count -eq 0) { Out-Rep 'Aucun process Java ni JVM chargee.' } else { Out-RepObj ($rows | Sort-Object PID | Format-Table -AutoSize) }

foreach ($p in ($javaProcs | Where-Object { $FlagPids.ContainsKey([int]$_.ProcessId) })) {
    $pidv = [int]$p.ProcessId
    $cl = [string]$p.CommandLine
    $jvm = $jvmOf[$pidv]
    Out-Rep ''
    Out-Rep ('--- Process {0} ({1}) ---' -f $pidv, $p.Name)
    Out-Rep ('Demarre le      : {0}' -f $p.CreationDate)
    Out-Rep ('Executable      : {0}' -f $p.ExecutablePath)
    Out-Rep ('JVM chargee     : {0}' -f $jvm)
    if ($jvm) {
        try { Out-Rep ('Version JVM     : {0}' -f (Get-Item -LiteralPath $jvm -ErrorAction Stop).VersionInfo.ProductVersion) } catch { }
        if (-not $St.DefaultJH) { $St.DefaultJH = Get-JavaHomeFromPath $jvm }
    } elseif ($p.ExecutablePath -match '(?i)\\javaw?\.exe$') {
        if (-not $St.DefaultJH) { $St.DefaultJH = Get-JavaHomeFromPath $p.ExecutablePath }
    }
    $props = [regex]::Matches($cl, '-D(weblogic\.Name|DOMAIN_HOME|domain\.home|oracle\.home|ORACLE_HOME|common\.components\.home|wls\.home|weblogic\.home|odi\.[\w.]+|oracle\.odi[\w.]*|agent[\w.]*)=("[^"]*"|\S+)')
    if ($props.Count -gt 0) {
        Out-Rep 'Proprietes utiles :'
        foreach ($m in $props) { Out-Rep ('  ' + (Hide-Secret $m.Value)) }
    }
    $clm = Hide-Secret $cl
    if ($clm.Length -gt 1500) { $clm = $clm.Substring(0, 1500) + ' [...]' }
    Out-Rep 'Ligne de commande (masquee, 1500 premiers caracteres) :'
    Out-Rep ('  ' + $clm)

    if ($cl -match 'weblogic\.Server') { $St.WlsRunning = $true }
    if ($cl -match 'weblogic\.NodeManager') { $St.NmRunning = $true }
    if ($cl -match '(?i)oracle\.odi|odi.*Agent|Agent.*odi' -or $p.Name -match '(?i)^odi') { $St.OdiRunning = $true }
    if ($cl -match '(?i)oam_server|oam-server') { $OamWhere.Add("process:$pidv") }
    if ($cl -match '(?i)bi_server|obis') { $BiWhere.Add("process:$pidv") }

    # Oracle Home deduit du chemin de l'executable (ex. ...\Oracle_Home\odi\studio\odi64.exe)
    if ($p.ExecutablePath -match '^(?i)(.+?)\\odi\\studio\\') { Add-OH $Matches[1] ("chemin du process {0}" -f $pidv) }
    $v = Get-Prop $cl 'oracle.home';            if ($v) { Add-OH $v ("process {0} -Doracle.home" -f $pidv) }
    $v = Get-Prop $cl 'ORACLE_HOME';            if ($v) { Add-OH $v ("process {0} -DORACLE_HOME" -f $pidv) }
    $v = Get-Prop $cl 'common.components.home'; if ($v) { Add-OH (Split-Path $v -Parent) ("process {0} -Dcommon.components.home" -f $pidv) }
    $v = Get-Prop $cl 'wls.home';               if ($v) { Add-OH (Split-Path (Split-Path $v -Parent) -Parent) ("process {0} -Dwls.home" -f $pidv) }
    $v = Get-Prop $cl 'DOMAIN_HOME';            if ($v) { Add-Dom $v ("process {0} -DDOMAIN_HOME" -f $pidv) }
    $v = Get-Prop $cl 'domain.home';            if ($v) { Add-Dom $v ("process {0} -Ddomain.home" -f $pidv) }
}

# ---------------------------------------------------------------------------
# 2. Recherche des Oracle Homes
# ---------------------------------------------------------------------------
Out-Section '2. RECHERCHE DES ORACLE HOMES ET DOMAINES'

$regRoots = @('HKLM:\SOFTWARE\Oracle', 'HKLM:\SOFTWARE\WOW6432Node\Oracle')
$invLocs = New-Object System.Collections.Generic.List[string]
Out-Rep 'Registre Oracle :'
foreach ($k in $regRoots) {
    if (-not (Test-Path -LiteralPath $k)) { Out-Rep ('  {0} : absent' -f $k); continue }
    $il = (Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue).inst_loc
    if ($il) { $invLocs.Add($il); Out-Rep ('  {0} inst_loc = {1}' -f $k, $il) }
    foreach ($sub in (Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue)) {
        $pr = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
        Out-Rep ('  {0}\{1} : ORACLE_HOME = {2}' -f $k, $sub.PSChildName, $pr.ORACLE_HOME)
        if ($pr.ORACLE_HOME) { Add-OH $pr.ORACLE_HOME ('registre {0}' -f $sub.PSChildName) }
    }
}
$invLocs.Add('C:\Program Files\Oracle\Inventory')

foreach ($inv in ($invLocs | Select-Object -Unique)) {
    try { $x = Join-Path $inv 'ContentsXML\inventory.xml' -ErrorAction Stop } catch { continue }
    if (-not (Test-Path -LiteralPath $x)) { continue }
    Out-Rep ('Inventaire central : {0}' -f $x)
    $c = Get-Content -LiteralPath $x -Raw -ErrorAction SilentlyContinue
    foreach ($m in [regex]::Matches($c, '<HOME [^>]*>')) {
        $loc = Get-XmlAttr $m.Value 'LOC'
        $nm = Get-XmlAttr $m.Value 'NAME'
        if ((Get-XmlAttr $m.Value 'REMOVED') -eq 'T') {
            Out-Rep ('  - {0} : {1} (supprime de l''inventaire)' -f $nm, $loc)
        } else {
            Out-Rep ('  - {0} : {1}' -f $nm, $loc)
            Add-OH $loc 'inventaire central'
        }
    }
}

if (-not $NoDiskSearch) {
    Out-Rep ''
    Out-Rep 'Parcours des disques locaux (dossiers OPatch), hors \Windows :'
    $drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | ForEach-Object { $_.DeviceID + '\' })
    foreach ($d in $drives) {
        Out-Rep ('  disque : {0}' -f $d)
        $tops = Get-ChildItem -LiteralPath $d -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @('Windows', '$Recycle.Bin', 'System Volume Information', 'Recovery') }
        foreach ($t in $tops) {
            if ($t.Name -ieq 'OPatch') { if (Test-HomeShape $d) { Add-OH $d 'disque (OPatch)' } }
            Get-ChildItem -LiteralPath $t.FullName -Directory -Recurse -Force -Filter 'OPatch' -ErrorAction SilentlyContinue |
                Where-Object { Test-HomeShape $_.Parent.FullName } |
                ForEach-Object { Add-OH $_.Parent.FullName ('disque ({0})' -f $d) }
        }
    }
}

# Domaines : emplacements usuels autour de chaque Oracle Home
foreach ($oh in @($OHs)) {
    foreach ($base in @((Join-Path $oh 'user_projects\domains'), (Join-Path (Split-Path $oh -Parent) 'user_projects\domains'))) {
        if (Test-Path -LiteralPath $base) {
            Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue | ForEach-Object { Add-Dom $_.FullName 'user_projects\domains' }
        }
    }
}
Out-Rep ''
Out-Rep ('Oracle Homes retenus : {0} ; domaines WebLogic/ODI retenus : {1}' -f $OHs.Count, $Doms.Count)

# ---------------------------------------------------------------------------
# 3. Analyse des Oracle Homes
# ---------------------------------------------------------------------------
Out-Section '3. ANALYSE DES ORACLE HOMES'
if ($OHs.Count -eq 0) { Out-Rep 'Aucun Oracle Home trouve.' }

foreach ($oh in @($OHs)) {
    Out-Rep ''
    Out-Rep ('### Oracle Home : {0}' -f $oh)
    try { Out-Rep ('Proprietaire    : {0}' -f (Get-Acl -LiteralPath $oh -ErrorAction Stop).Owner) } catch { }

    $type = 'indetermine'
    if ((Test-Path -LiteralPath (Join-Path $oh 'bin\oracle.exe')) -or (Test-Path -LiteralPath (Join-Path $oh 'rdbms'))) {
        $type = 'ORACLE DATABASE (serveur)'
    } elseif ((Test-Path -LiteralPath (Join-Path $oh 'inventory\registry.xml')) -or (Test-Path -LiteralPath (Join-Path $oh 'oracle_common'))) {
        $type = 'Fusion Middleware 12c+'
    } elseif (Test-Path -LiteralPath (Join-Path $oh 'bin\sqlplus.exe')) {
        $type = 'client Oracle'
    }
    Out-Rep ('Type            : {0}' -f $type)

    if ($type -eq 'ORACLE DATABASE (serveur)') {
        $St.DbFound = $true; $DbHomes.Add($oh)
        Out-Rep '(Home de base de donnees : hors perimetre des CVE Fusion Middleware, voir section 7)'
        continue
    }

    $reg = Join-Path $oh 'inventory\registry.xml'
    $comps = Join-Path $oh 'inventory\ContentsXML\comps.xml'
    if (Test-Path -LiteralPath $reg) {
        $rc = Get-Content -LiteralPath $reg -Raw -ErrorAction SilentlyContinue
        Out-Rep 'Distributions (inventory\registry.xml) :'
        foreach ($m in [regex]::Matches($rc, '<distribution [^>]*>')) {
            Out-Rep ('  - {0} | version {1} | {2}' -f (Get-XmlAttr $m.Value 'name'), (Get-XmlAttr $m.Value 'version'), (Get-XmlAttr $m.Value 'status'))
        }
        Out-Rep 'Fonctionnalites liees aux CVE (inventory\registry.xml) :'
        $feats = foreach ($m in [regex]::Matches($rc, '<feature [^>]*>')) {
            $n = Get-XmlAttr $m.Value 'name'
            if ($n -match '(?i)data integrator|weblogic|jps|opss|platform security|access manager|business intelligence|delivery platform') {
                '  - {0} | {1}' -f $n, (Get-XmlAttr $m.Value 'version')
            }
        }
        foreach ($f in ($feats | Sort-Object -Unique | Select-Object -First 40)) { Out-Rep $f }
    } elseif (Test-Path -LiteralPath $comps) {
        Out-Rep 'Composants (inventory\ContentsXML\comps.xml, 25 premiers) :'
        $cc = Get-Content -LiteralPath $comps -Raw -ErrorAction SilentlyContinue
        foreach ($m in ([regex]::Matches($cc, '<COMP NAME="[^"]*" VER="[^"]*"') | Select-Object -First 25)) { Out-Rep ('  - ' + $m.Value.Substring(6)) }
    }

    Out-Rep 'Presence de composants :'
    if (Show-Presence $oh 'odi' 'Oracle Data Integrator') { $OdiHomes.Add($oh) }
    [void](Show-Presence $oh 'odi\agent' 'agent ODI')
    [void](Show-Presence $oh 'odi\studio' 'ODI Studio')
    if (Show-Presence $oh 'wlserver\server\lib\weblogic.jar' 'WebLogic Server -> CVE-2026-91569') { $WlsHomes.Add($oh) }
    $jps = @(Get-ChildItem -LiteralPath (Join-Path $oh 'oracle_common\modules') -Directory -Filter 'oracle.jps*' -ErrorAction SilentlyContinue)
    if ($jps.Count -gt 0) {
        Out-Rep ('  [OUI] {0,-42} {1}' -f 'oracle_common\modules\oracle.jps*', 'OPSS -> CVE-2026-114824')
        $OpssHomes.Add($oh)
    } else {
        Out-Rep ('  [non] {0,-42} {1}' -f 'oracle_common\modules\oracle.jps*', 'OPSS -> CVE-2026-114824')
    }
    [void](Show-Presence $oh 'oracle_common\modules\thirdparty' 'jars tiers centralises (composant de la CVE-2026-114824)')
    if (Show-Presence $oh 'idm' 'Identity & Access (OAM) -> CVE-2026-114835/-91500/-91510') { $OamWhere.Add((Join-Path $oh 'idm')) }
    if (Show-Presence $oh 'bi' 'Business Intelligence (OBIEE) -> CVE-2026-114784') { $BiWhere.Add((Join-Path $oh 'bi')) }
    $sdp = Get-ChildItem -LiteralPath $oh -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)sdp|^communications$' } | Select-Object -First 1
    if ($sdp) {
        Out-Rep ('  [OUI] {0,-42} {1}' -f $sdp.Name, 'Service Delivery Platform ? -> CVE-2026-91558 (heuristique)')
        $SdpWhere.Add($sdp.FullName)
    } else {
        Out-Rep ('  [non] {0,-42} {1}' -f '*sdp* / communications', 'Service Delivery Platform -> CVE-2026-91558 (heuristique)')
    }
    [void](Show-Presence $oh 'ohs' 'Oracle HTTP Server')
    [void](Show-Presence $oh 'soa' 'SOA Suite')
    [void](Show-Presence $oh 'em' 'Enterprise Manager FMW Control')

    # JAVA_HOME pour OPatch
    $jh = ''
    $ge = Join-Path $oh 'oui\.globalEnv.properties'
    if (Test-Path -LiteralPath $ge) {
        $line = Get-Content -LiteralPath $ge -ErrorAction SilentlyContinue | Where-Object { $_ -match '^JAVA_HOME=' } | Select-Object -First 1
        if ($line) { $jh = ($line -replace '^JAVA_HOME=', '') -replace '\\(.)', '$1' }
        Out-Rep ('JAVA_HOME d''installation (oui\.globalEnv.properties) : {0}' -f $jh)
    }
    if (-not $jh -or -not (Test-Path -LiteralPath (Join-Path $jh 'bin\java.exe'))) { $jh = $St.DefaultJH }
    if (-not $jh) { $jh = [Environment]::GetEnvironmentVariable('JAVA_HOME', 'Machine') }
    Out-Rep ('JAVA_HOME utilise pour OPatch : {0}' -f $jh)

    $patchText = New-Object System.Collections.Generic.List[string]
    $opatch = Join-Path $oh 'OPatch\opatch.bat'
    if (Test-Path -LiteralPath $opatch) {
        if (-not $NoOPatch -and $jh) {
            $oldJH = $env:JAVA_HOME
            $env:JAVA_HOME = $jh
            Push-Location -LiteralPath $oh
            try {
                Out-Rep 'Version d''OPatch :'
                $ver = & $opatch version 2>&1 | ForEach-Object { "$_" }
                foreach ($l in ($ver | Select-Object -First 5)) { Out-Rep ('  ' + $l) }
                Out-Rep 'Patchs appliques (opatch lspatches) :'
                $lsp = & $opatch lspatches -oh $oh 2>&1 | ForEach-Object { "$_" }
                foreach ($l in $lsp) { Out-Rep ('  ' + $l); $patchText.Add($l) }
            } catch {
                Out-Rep ('  Erreur OPatch : {0}' -f $_.Exception.Message)
            } finally {
                Pop-Location
                $env:JAVA_HOME = $oldJH
            }
        } else {
            Out-Rep 'OPatch non lance (option -NoOPatch ou JAVA_HOME introuvable).'
        }
    } else {
        Out-Rep 'OPatch absent de cet Oracle Home.'
    }

    $fromFiles = @()
    $fromFiles += @(Get-ChildItem -LiteralPath (Join-Path $oh 'inventory\patches') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $fromFiles += @(Get-ChildItem -LiteralPath (Join-Path $oh '.patch_storage') -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $ids = @($fromFiles | ForEach-Object { if ($_ -match '^(\d{6,})') { $Matches[1] } } | Sort-Object -Unique)
    Out-Rep ('Patchs vus dans les fichiers d''inventaire (indicatif) : {0}' -f ($ids -join ' '))
    foreach ($i in $ids) { $patchText.Add($i) }

    if ($Expected.Count -gt 0 -and $type -eq 'Fusion Middleware 12c+') {
        Out-Rep 'Controle des patchs attendus (-ExpectedPatches) :'
        $all = $patchText -join "`n"
        foreach ($e in $Expected) {
            if ($all -match ('\b' + $e + '\b')) { Out-Rep ('  [present] {0}' -f $e) }
            else { Out-Rep ('  [ABSENT]  {0}' -f $e); $Missing.Add(('{0}:{1}' -f $oh, $e)) }
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Domaines WebLogic / ODI
# ---------------------------------------------------------------------------
Out-Section '4. DOMAINES WEBLOGIC / ODI'
if ($Doms.Count -eq 0) { Out-Rep 'Aucun domaine trouve.' }
foreach ($d in @($Doms)) {
    $cfg = Join-Path $d 'config\config.xml'
    Out-Rep ''
    Out-Rep ('### Domaine : {0}' -f $d)
    try { [xml]$x = Get-Content -LiteralPath $cfg -Raw -ErrorAction Stop } catch { Out-Rep '  config.xml illisible'; continue }
    $root = $x.DocumentElement
    Out-Rep ('Nom             : {0}' -f (Get-XmlChild $root 'name'))
    Out-Rep ('Version         : {0}' -f (Get-XmlChild $root 'domain-version'))
    Out-Rep ('Serveur d''admin : {0}' -f (Get-XmlChild $root 'admin-server-name'))
    Out-Rep 'Serveurs WebLogic declares (nom / adresse d''ecoute / port / port SSL) :'
    $servers = $root.SelectNodes("*[local-name()='server']")
    if ($servers.Count -eq 0) { Out-Rep '  (aucun serveur WebLogic declare)' }
    foreach ($srv in $servers) {
        $addr = Get-XmlChild $srv 'listen-address'; if (-not $addr) { $addr = 'toutes interfaces' }
        $port = Get-XmlChild $srv 'listen-port';    if (-not $port) { $port = '7001 (defaut)' }
        $ssl = $srv.SelectSingleNode("*[local-name()='ssl']/*[local-name()='listen-port']")
        if ($ssl) { $sslp = $ssl.InnerText } else { $sslp = '-' }
        Out-Rep ('  - {0} / {1} / {2} / {3}' -f (Get-XmlChild $srv 'name'), $addr, $port, $sslp)
    }
    Out-Rep 'Applications deployees (oraclediagent = agent JEE, odiconsole = ODI Console) :'
    $apps = @($root.SelectNodes("*[local-name()='app-deployment']/*[local-name()='name']") | ForEach-Object { $_.InnerText })
    if ($apps.Count -eq 0) { Out-Rep '  (aucune)' }
    foreach ($a in $apps) { Out-Rep ('  - ' + $a) }
    if ($apps -match '(?i)oraclediagent|odiconsole') { $JeeWhere.Add($d) }

    $odi = Join-Path $d 'config\fmwconfig\components\ODI'
    if (Test-Path -LiteralPath $odi) {
        Out-Rep ('Agents ODI declares dans le domaine : {0}' -f ((Get-ChildItem -LiteralPath $odi -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ' '))
        Out-Rep 'Parametres reseau des agents (port/host/protocol, mots de passe exclus) :'
        Get-ChildItem -LiteralPath $odi -Recurse -File -Include '*.properties', '*.xml' -ErrorAction SilentlyContinue | Select-Object -First 30 |
            Select-String -Pattern '(?i)port|host|protocol' -ErrorAction SilentlyContinue |
            Where-Object { $_.Line -notmatch '(?i)pass|pwd|secret|credential' } | Select-Object -First 60 |
            ForEach-Object { Out-Rep ('  {0}: {1}' -f $_.Path, (Hide-Secret $_.Line.Trim())) }
    }
    $nm = Join-Path $d 'nodemanager\nodemanager.properties'
    if (Test-Path -LiteralPath $nm) {
        Out-Rep 'Node Manager (nodemanager.properties) :'
        Get-Content -LiteralPath $nm | Where-Object { $_ -match '^(ListenAddress|ListenPort|SecureListener)=' } | ForEach-Object { Out-Rep ('  ' + $_) }
    }
}

# ---------------------------------------------------------------------------
# 5. Ports TCP en ecoute
# ---------------------------------------------------------------------------
Out-Section '5. PORTS TCP EN ECOUTE'
$conns = $null
try { $conns = @(Get-NetTCPConnection -State Listen -ErrorAction Stop) } catch { }
if ($conns) {
    $prow = foreach ($c in ($conns | Sort-Object LocalPort, LocalAddress)) {
        $pidv = [int]$c.OwningProcess
        if ($c.LocalAddress -match '^(127\.|::1$)') { $expo = 'local' } else { $expo = 'reseau' }
        $mark = '-'
        if ($FlagPids.ContainsKey($pidv)) {
            $mark = 'ODI/FMW'
            $ListenFlag.Add(('{0}:{1} ({2}, pid {3})' -f $c.LocalAddress, $c.LocalPort, $expo, $pidv))
        }
        [pscustomobject]@{ Marque = $mark; Adresse = $c.LocalAddress; Port = $c.LocalPort; Expo = $expo; PID = $pidv; Process = $procName[$pidv] }
    }
    Out-RepObj ($prow | Format-Table -AutoSize)
} else {
    Out-Rep 'Get-NetTCPConnection indisponible ; sortie netstat -ano (LISTENING) :'
    netstat -ano | Select-String 'LISTENING' | ForEach-Object { Out-Rep ('  ' + $_.Line.Trim()) }
}

# ---------------------------------------------------------------------------
# 6. Pare-feu Windows
# ---------------------------------------------------------------------------
Out-Section '6. PARE-FEU WINDOWS'
try {
    Out-RepObj (Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction | Format-Table -AutoSize)
} catch {
    Out-Rep 'Profils de pare-feu non lisibles.'
}

# ---------------------------------------------------------------------------
# 7. Bases de donnees Oracle
# ---------------------------------------------------------------------------
Out-Section '7. BASES DE DONNEES ORACLE'
Out-Rep 'Services Windows dont le nom contient Oracle :'
$svc = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)oracle' -or $_.DisplayName -match '(?i)oracle' })
if ($svc.Count -eq 0) { Out-Rep '  aucun' } else {
    Out-RepObj ($svc | Select-Object Name, State, StartMode, StartName, PathName | Format-Table -AutoSize -Wrap)
    if ($svc | Where-Object { $_.Name -match '(?i)^OracleService|TNSListener' }) { $St.DbFound = $true }
}
Out-Rep 'Process d''instance ou de listener Oracle (oracle.exe, tnslsnr.exe) :'
$dbp = @($wmi | Where-Object { $_.Name -match '^(?i)(oracle|tnslsnr)\.exe$' })
if ($dbp.Count -eq 0) { Out-Rep '  aucun' } else {
    $St.DbFound = $true
    Out-RepObj ($dbp | Select-Object ProcessId, Name, ExecutablePath | Format-Table -AutoSize)
}
if ($DbHomes.Count -gt 0) { Out-Rep ('Oracle Homes de type base de donnees : {0}' -f ($DbHomes -join ' ; ')) } else { Out-Rep 'Oracle Homes de type base de donnees : aucun' }

# ---------------------------------------------------------------------------
# 8. Synthese
# ---------------------------------------------------------------------------
Out-Section '8. SYNTHESE PRELIMINAIRE (a valider par l''analyste)'
if ($St.DbFound) { Out-Rep 'Base de donnees Oracle : DETECTEE (voir sections 3 et 7)' } else { Out-Rep 'Base de donnees Oracle : aucune detectee' }
Out-Rep ('Oracle Homes           : {0}' -f $OHs.Count)
if ($OdiHomes.Count -gt 0) { Out-Rep ('ODI installe           : oui -> {0}' -f ($OdiHomes -join ' ; ')) } else { Out-Rep 'ODI installe           : non' }
if ($St.OdiRunning) { Out-Rep 'ODI en execution       : oui (Studio ou agent, voir section 1)' } else { Out-Rep 'ODI en execution       : non detecte' }
if ($ListenFlag.Count -gt 0) { Out-Rep ('Ports ODI/FMW ecoutes  : {0}' -f ($ListenFlag -join ' ; ')) } else { Out-Rep 'Ports ODI/FMW ecoutes  : aucun' }
Out-Rep ''
Out-Rep 'CVE-2026-91569 (WebLogic Server, CVSS 10.0)'
if ($St.WlsRunning) {
    Out-Rep '  => A ANALYSER : un serveur WebLogic est EN EXECUTION. Patch et exposition reseau a traiter.'
} elseif ($St.NmRunning) {
    Out-Rep '  => A ANALYSER : Node Manager WebLogic en execution (aucun serveur WebLogic lance au moment du releve).'
} elseif ($WlsHomes.Count -gt 0) {
    Out-Rep ('  => A ANALYSER : binaires WebLogic presents mais aucun serveur lance ({0}).' -f ($WlsHomes -join ' ; '))
    Out-Rep '     Exposition nulle tant qu''il n''est pas lance ; le patch reste a appliquer.'
} elseif ($JeeWhere.Count -gt 0) {
    Out-Rep ('  => A VERIFIER : un domaine declare un agent JEE ou ODI Console ({0}) mais les binaires WebLogic n''ont pas ete trouves.' -f ($JeeWhere -join ' ; '))
} else {
    Out-Rep '  => NON CONCERNE : WebLogic Server absent.'
}
Out-Rep 'CVE-2026-114824 (Oracle Platform Security for Java, CVSS 10.0)'
if ($OpssHomes.Count -gt 0) {
    Out-Rep ('  => A ANALYSER : librairies OPSS presentes ({0}).' -f ($OpssHomes -join ' ; '))
    Out-Rep '     Exploitable seulement via un service HTTP qui les charge : voir les ports ODI/FMW ci-dessus.'
    Out-Rep '     Un ODI Studio (client lourd, sans port en ecoute) n''offre pas cette surface ; le patch reste a appliquer.'
} else {
    Out-Rep '  => NON CONCERNE : OPSS absent des Oracle Homes trouves.'
}
Out-Rep 'CVE-2026-114835 / CVE-2026-91500 / CVE-2026-91510 (Oracle Access Manager, CVSS 10.0)'
if ($OamWhere.Count -gt 0) { Out-Rep ('  => A ANALYSER : indices OAM -> {0}' -f ($OamWhere -join ' ; ')) } else { Out-Rep '  => NON CONCERNE : aucun composant OAM trouve.' }
Out-Rep 'CVE-2026-114784 (Oracle Business Intelligence Enterprise Edition, CVSS 10.0)'
if ($BiWhere.Count -gt 0) { Out-Rep ('  => A ANALYSER : indices OBIEE -> {0}' -f ($BiWhere -join ' ; ')) } else { Out-Rep '  => NON CONCERNE : aucun composant OBIEE trouve.' }
Out-Rep 'CVE-2026-91558 (Service Delivery Platform, CVSS 8.3)'
if ($SdpWhere.Count -gt 0) { Out-Rep ('  => A VERIFIER (detection heuristique) -> {0}' -f ($SdpWhere -join ' ; ')) } else { Out-Rep '  => NON CONCERNE : aucun composant SDP trouve.' }
Out-Rep ''
if ($Expected.Count -gt 0) {
    if ($Missing.Count -gt 0) { Out-Rep ('Patchs attendus absents : {0}' -f ($Missing -join ' ; ')) } else { Out-Rep 'Patchs attendus absents : aucun' }
} else {
    Out-Rep 'Patchs attendus : non controles (-ExpectedPatches non fourni). Comparer la section 3 au Patch Availability Document.'
}
Out-Rep ''
Out-Rep ('Rapport : {0}' -f $Report)
