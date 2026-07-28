<#
.SYNOPSIS
    Diagnose why an AI Server can (or can't) be reached, and print the address to give clients.

.DESCRIPTION
    Answers the question admins actually have — "why can't the other machine connect?" — by checking
    the whole chain in the order it breaks:

        1. Is the server process listening at all, and on which addresses?
        2. Is it bound to the network, or only to this machine (loopback)?
        3. Does the Windows Firewall really allow that port on the ACTIVE network profile?
        4. Is the network marked Public, where Windows blocks far more?
        5. Does the API answer, and is authentication actually enforced?

    Every check that can fail prints the specific fix. Run it locally on the server for the full
    picture, or with -RemoteHost from a client machine to test reachability across the network.

.PARAMETER Port
    The port AI Server is listening on (see AI Server's Server page). Default 11436.

.PARAMETER RemoteHost
    Check a server on ANOTHER machine. Local-only checks (listening scope, firewall) are skipped.

.PARAMETER ApiKey
    An AI Server API key. Optional: without it the script still verifies that the API refuses
    unauthenticated requests, which is itself a useful result.

.EXAMPLE
    .\Check-AIServer.ps1 -Port 11436
    Full local diagnosis on the machine running AI Server.

.EXAMPLE
    .\Check-AIServer.ps1 -RemoteHost 192.168.1.42 -Port 11436 -ApiKey $env:AISERVER_API_KEY
    Check from a client machine whether the server is reachable and working.
#>
[CmdletBinding()]
param(
    [int]$Port = 11436,
    [string]$RemoteHost,
    [string]$ApiKey = $env:AISERVER_API_KEY
)

$ErrorActionPreference = 'Continue'
$script:Problems = 0

function Write-Check {
    param([string]$Title, [ValidateSet('OK', 'WARN', 'FAIL', 'INFO')][string]$State, [string]$Detail)
    $colour = @{ OK = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$State]
    Write-Host ("  [{0,-4}] " -f $State) -ForegroundColor $colour -NoNewline
    Write-Host $Title -ForegroundColor White
    if ($Detail) { $Detail -split "`n" | ForEach-Object { Write-Host "         $_" -ForegroundColor Gray } }
    if ($State -eq 'FAIL') { $script:Problems++ }
}

$isRemote = -not [string]::IsNullOrWhiteSpace($RemoteHost)
$targetHost = if ($isRemote) { $RemoteHost } else { '127.0.0.1' }

Write-Host "`nAI Server diagnostics" -ForegroundColor White
Write-Host ("Target: {0}:{1}{2}`n" -f $targetHost, $Port, $(if ($isRemote) { ' (remote)' } else { ' (this machine)' })) -ForegroundColor Gray

# ── 1. Listening scope (local only — needs this machine's socket table) ─────────
if (-not $isRemote) {
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
    if (-not $listeners) {
        Write-Check 'Server process listening' 'FAIL' @'
Nothing is listening on this port.
Start AI Server (This session -> Start, or the Windows service), or check the
port on AI Server's Server page -- an auto-picked port may differ from the default.
'@
    } else {
        $addresses = $listeners.LocalAddress | Sort-Object -Unique
        $allInterfaces = $addresses | Where-Object { $_ -in '0.0.0.0', '::' }
        if ($allInterfaces) {
            Write-Check 'Server process listening' 'OK' "Bound to all interfaces ($($addresses -join ', ')) - reachable from the network."
        } else {
            Write-Check 'Server process listening' 'FAIL' @"
Listening only on $($addresses -join ', ') - LOOPBACK. Other computers cannot connect,
no matter what the firewall allows.
Fix: AI Server -> Server settings -> Access -> "This network", Save, then restart the
server (or Stop/Start the Windows service). Network serving requires Pro.
"@
        }
    }
}

# ── 2. Firewall: does a rule really apply on the ACTIVE profile? ────────────────
if (-not $isRemote) {
    $profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
    $activeCategories = @($profiles.NetworkCategory | Sort-Object -Unique)

    if ($activeCategories -contains 'Public') {
        Write-Check 'Network type' 'WARN' @'
This network is set to PUBLIC, where Windows blocks incoming connections aggressively
and rules scoped to Private/Domain do not apply.
Fix (home/office): Settings -> Network & internet -> your network -> Private,
or:  Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private
'@
    } else {
        Write-Check 'Network type' 'OK' "Active profile(s): $($activeCategories -join ', ')"
    }

    # A BLOCK rule beats any allow rule, and Windows creates them silently when its
    # "Allow access?" prompt is dismissed -- the most-missed cause of an unreachable server.
    $blockRules = @(Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { (($_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program) -like '*aisuite-server*' })
    if ($blockRules) {
        Write-Check 'Firewall block rules' 'FAIL' @"
$($blockRules.Count) inbound BLOCK rule(s) exist for AI Server. These OVERRIDE any allow rule.
Windows adds these when its "Allow access?" prompt is dismissed.
Fix (run as administrator):
  Get-NetFirewallRule -Direction Inbound -Action Block |
    Where-Object { (`$_ | Get-NetFirewallApplicationFilter).Program -like '*aisuite-server*' } |
    Remove-NetFirewallRule
"@
    } else {
        Write-Check 'Firewall block rules' 'OK' 'No blocking rules for AI Server.'
    }

    # An allow rule only counts if it covers this port AND applies to a live profile.
    $allowRules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { ($_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue).LocalPort -contains "$Port" })
    if ($allowRules) {
        $ruleProfiles = ($allowRules.Profile -join ',')
        $covers = $activeCategories.Count -eq 0 -or ($allowRules | Where-Object {
            $_.Profile -eq 'Any' -or ($activeCategories | Where-Object { $_ -and $ruleProfiles -match $_ }) })
        if ($covers) {
            Write-Check "Firewall allow rule for port $Port" 'OK' "Rule profile(s): $ruleProfiles"
        } else {
            Write-Check "Firewall allow rule for port $Port" 'FAIL' @"
A rule exists but its profile(s) ($ruleProfiles) do not include the active network
($($activeCategories -join ', ')), so it permits nothing.
Fix (administrator):  netsh advfirewall firewall set rule name="AI Server ($Port)" new profile=any
"@
        }
    } else {
        Write-Check "Firewall allow rule for port $Port" 'FAIL' @"
No inbound allow rule covers port $Port. Other computers will be refused.
Fix (administrator):
  netsh advfirewall firewall add rule name="AI Server ($Port)" dir=in action=allow ``
    protocol=TCP localport=$Port profile=private,domain
(Add ,public only if this network must stay Public.)
"@
    }
}

# ── 3. TCP reachability ────────────────────────────────────────────────────────
$tcp = Test-NetConnection -ComputerName $targetHost -Port $Port -WarningAction SilentlyContinue
if ($tcp.TcpTestSucceeded) {
    Write-Check "TCP connect to ${targetHost}:$Port" 'OK' 'Port is reachable.'
} else {
    Write-Check "TCP connect to ${targetHost}:$Port" 'FAIL' $(if ($isRemote) {
@"
Cannot reach the port from this machine.
Run this script ON the server with no -RemoteHost to see whether it is a bind,
firewall or network-profile problem. Also confirm the port on the Server page --
with "Auto-pick a free port" enabled it can differ from what you expect.
"@
    } else { 'The port is not accepting connections even locally.' })
}

# ── 4. The API itself ──────────────────────────────────────────────────────────
$base = "http://${targetHost}:$Port"

function Invoke-Api {
    param([string]$Path, [hashtable]$Headers = @{})
    try {
        $r = Invoke-WebRequest -Uri "$base$Path" -Headers $Headers -TimeoutSec 20 `
                               -UseBasicParsing -ErrorAction Stop
        [pscustomobject]@{ Code = [int]$r.StatusCode; Body = $r.Content }
    } catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        [pscustomobject]@{ Code = $code; Body = '' }
    }
}

if ($tcp.TcpTestSucceeded) {
    $version = Invoke-Api '/api/version'
    if ($version.Code -eq 200) {
        Write-Check 'API responding' 'OK' "GET /api/version -> $($version.Body.Trim())"
    } else {
        Write-Check 'API responding' 'FAIL' "GET /api/version returned $($version.Code). Something else may be using this port."
    }

    # Unauthenticated request MUST be refused once the server is on a network.
    $anon = Invoke-Api '/v1/models'
    if ($anon.Code -eq 401) {
        Write-Check 'Authentication enforced' 'OK' 'Unauthenticated /v1/models correctly refused (401).'
    } elseif ($anon.Code -eq 200) {
        Write-Check 'Authentication enforced' 'WARN' @'
/v1/models answered WITHOUT a key. Expected on a loopback-only server; on a network
server this would mean anyone who can reach the port can use your models.
'@
    } else {
        Write-Check 'Authentication enforced' 'INFO' "Unauthenticated /v1/models returned $($anon.Code)."
    }

    if ($ApiKey) {
        $auth = Invoke-Api '/v1/models' @{ Authorization = "Bearer $ApiKey" }
        if ($auth.Code -eq 200) {
            $count = ([regex]::Matches($auth.Body, '"id"\s*:')).Count
            Write-Check 'API key accepted' 'OK' "$count model(s) available."
        } elseif ($auth.Code -eq 401) {
            Write-Check 'API key accepted' 'FAIL' @'
The key was rejected (401). Issue a fresh one in AI Server -> API keys.
Keys apply immediately -- the server does not need restarting.
'@
        } else {
            Write-Check 'API key accepted' 'FAIL' "GET /v1/models returned $($auth.Code) with the key."
        }
    } else {
        Write-Check 'API key check' 'INFO' 'No key supplied. Pass -ApiKey or set AISERVER_API_KEY to test one.'
    }
}

# ── 5. The address to hand to clients ──────────────────────────────────────────
if (-not $isRemote) {
    $lan = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address } |
           Select-Object -First 1 -ExpandProperty IPv4Address | Select-Object -First 1
    if ($lan) {
        Write-Host "`nAddress for other computers:" -ForegroundColor White
        Write-Host "  http://$($lan.IPAddress):$Port/v1" -ForegroundColor Cyan
        Write-Host "  (base URL for OpenAI-compatible clients; a key is required)`n" -ForegroundColor Gray
    }
}

if ($script:Problems -eq 0) {
    Write-Host "No problems found.`n" -ForegroundColor Green
    exit 0
}
Write-Host "$script:Problems problem(s) found - see the fixes above.`n" -ForegroundColor Red
exit 1
