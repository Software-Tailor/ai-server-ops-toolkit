# AI Server ops toolkit

One script that answers the question every admin actually has about
**[Software Tailor AI Server](https://softwaretailor.com/docs/ai-server/index.htm)**:

> *"Why can't the other machine connect?"*

It checks the whole chain **in the order it breaks**, and every failure prints the specific fix.

```console
PS> .\Check-AIServer.ps1 -Port 11436

AI Server diagnostics
Target: 127.0.0.1:11436 (this machine)

  [FAIL] Server process listening
         Listening only on 127.0.0.1 - LOOPBACK. Other computers cannot connect,
         no matter what the firewall allows.
         Fix: AI Server -> Server settings -> Access -> "This network", Save, then restart the
         server (or Stop/Start the Windows service). Network serving requires Pro.
  [OK  ] Network type
         Active profile(s): Private
  [OK  ] Firewall block rules
         No blocking rules for AI Server.
  [FAIL] Firewall allow rule for port 11436
         No inbound allow rule covers port 11436. Other computers will be refused.
         Fix (administrator):
           netsh advfirewall firewall add rule name="AI Server (11436)" dir=in action=allow `
             protocol=TCP localport=11436 profile=private,domain
```

## Run it

**On the server** (full diagnosis — listening scope, firewall, network type, API):

```powershell
.\Check-AIServer.ps1 -Port 11436
```

**From a client machine** (is it reachable from here, and does auth work?):

```powershell
.\Check-AIServer.ps1 -RemoteHost 192.168.1.42 -Port 11436 -ApiKey $env:AISERVER_API_KEY
```

Windows PowerShell 5.1 or PowerShell 7+. No modules to install. The script only reads state and makes
HTTP requests — it changes nothing; the fixes are printed for you to run. Exit code is `0` when clean,
`1` when something needs attention, so it works in a monitoring check.

## What it checks, and why each one exists

Every check below corresponds to a real way a working-looking server ends up unreachable:

| Check | The failure it catches |
| --- | --- |
| **Listening scope** | The server is running, but bound to `127.0.0.1` only. No firewall change can help — this is the single most common cause, and it looks identical to a firewall problem from the client side. |
| **Network type** | Windows marks any network you didn't explicitly trust as **Public** and blocks far more there. A rule scoped Private/Domain then permits nothing — the server looks configured, yet every remote connection is refused. |
| **Firewall BLOCK rules** | Windows *silently creates* inbound block rules for a program when its "Allow access?" prompt is dismissed. **Deny beats allow**, so adding allow rules afterwards changes nothing. |
| **Firewall ALLOW rule** | Verifies a rule covers this port *and* applies to the profile that's actually active. |
| **TCP connect** | Confirms the port genuinely accepts connections from where you're running the script. |
| **API responding** | `GET /api/version` — proves it's AI Server on that port and not something else. |
| **Authentication enforced** | An unauthenticated `/v1/models` must be refused. If it answers, anyone who can reach the port can use your models. |
| **API key accepted** | Your key works and returns the model list. |
| **Address for clients** | Prints the LAN base URL to hand out — the exact string other machines need. |

## Ports move

If you leave **"Auto-pick a free port"** enabled, the port can differ from the default — check AI Server's
**Server** page for the current one and pass it with `-Port`. For a machine that serves other devices,
a **fixed port** is usually better: one firewall rule, one address to hand out, nothing to re-point.

## Common fixes

**Loopback only.** AI Server → **Server settings → Access → "This network"** → Save → restart the server
(or Stop/Start the Windows service). Network serving is a Pro feature.

**Network is Public.** For a home or office network:

```powershell
Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private
```

**Blocking rules exist** (administrator):

```powershell
Get-NetFirewallRule -Direction Inbound -Action Block |
  Where-Object { ($_ | Get-NetFirewallApplicationFilter).Program -like '*aisuite-server*' } |
  Remove-NetFirewallRule
```

**No allow rule** (administrator):

```powershell
netsh advfirewall firewall add rule name="AI Server (11436)" dir=in action=allow `
  protocol=TCP localport=11436 profile=private,domain
```

AI Server's own **Network diagnostics → Test connectivity** performs the equivalent checks in the app and
can add the rule for you; this script is for scripting it, checking from a client, or monitoring.

## Learn more

- [AI Server administration](https://softwaretailor.com/docs/ai-server/index.htm)
- [ai-server-quickstarts](https://github.com/Software-Tailor/ai-server-quickstarts) — the API in five languages
- [ai-server-dropin-recipes](https://github.com/Software-Tailor/ai-server-dropin-recipes) — point existing tools at your server

## Licence

[MIT](LICENSE).
