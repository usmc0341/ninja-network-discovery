<#
.SYNOPSIS
  NinjaOne: Local SSL & Port Enumerator (Windows)
.DESCRIPTION
  Gathers:
    - Open ports & owning processes (Open Ports & Services)
    - SSL certificate details for listening ports that speak TLS (SSL Certificate Info)
    - TLS protocol support and negotiated cipher (approximate) per SSL port (SSL Cipher Suites)

  Writes results into NinjaOne custom fields (WYSIWYG):
    - sslCertInfo
    - sslCipherSuites
    - openPortsInfo

  Notes:
    - Uses built-in .NET SslStream for handshakes. Cannot enumerate every server cipher suite the same way OpenSSL can,
      but will attempt handshakes with different SslProtocols and capture the negotiated cipher when successful.
    - Run as Administrator to map PIDs -> process names.
.AUTHOR
  Generated for Orion (cybersecurity) — adapt as needed.
#>

#region config & logging
[CmdletBinding()]
param(
    [string]$FieldCert = "sslCertInfo",
    [string]$FieldCiphers = "sslCipherSuites",
    [string]$FieldPorts = "openPortsInfo",
    [int]$HandshakeTimeoutSec = 5
)

# Logging
$LogFile = "$env:TEMP\Ninja_Scan_SSL_and_Ports.log"
"==== Starting run: $(Get-Date -Format o) ====" | Out-File -FilePath $LogFile -Encoding utf8 -Append
function Log {
    param([string]$m)
    $line = "$(Get-Date -Format o) `t $m"
    $line | Out-File -FilePath $LogFile -Encoding utf8 -Append
    Write-Verbose $m
}
#endregion

#region helpers (types & small doc)
# Complexity notes:
# - Port enumeration: O(P) where P = number of listening connections
# - TLS test loops: O(P * T) where T = number of protocol variants tested (small constant, ~3-4)
# - If you add cipher-by-cipher checks complexity becomes O(P * C) where C = #ciphers tested (can be large)
# This script uses T-based checks for practical runtime.

# Returns a string safe for NinjaOne field set
function Escape-ForNinja([string]$s) {
    if ($null -eq $s) { return "" }
    return $s -replace "`0",""  # remove nulls that break CLI
}
#endregion

#region ninja field setter (try cmdlet, fallback to CLI)
function Set-NinjaField {
    param(
        [string]$fieldName,
        [string]$value
    )
    $value = Escape-ForNinja $value
    # Try PowerShell cmdlet (if present)
    try {
        if (Get-Command -Name "Ninja-Property-Set" -ErrorAction SilentlyContinue) {
            Ninja-Property-Set -Name $fieldName -Value $value -ErrorAction Stop
            Log "Set field via Ninja-Property-Set: $fieldName"
            return $true
        }
    } catch {
        Log "Ninja-Property-Set failed: $($_.Exception.Message)"
    }

    # Fallback to CLI - common path for NinjaRMM agent
    $cliPaths = @(
        "$env:ProgramData\NinjaRMMAgent\ninjarmm-cli.exe",
        "$env:ProgramFiles\NinjaRMM\ninjarmm-cli.exe"
    )
    foreach ($p in $cliPaths) {
        if (Test-Path $p) {
            try {
                & $p set $fieldName $value 2>&1 | Out-Null
                Log "Set field via ninjarmm-cli: $fieldName (path $p)"
                return $true
            } catch {
                Log "ninjarmm-cli failed at $p : $($_.Exception.Message)"
            }
        }
    }

    Log "Could not set field $fieldName: Ninja CLI/cmdlet not found"
    return $false
}
#endregion

#region 1) open ports & mapping
Log "Enumerating listening TCP ports and processes..."
$portsList = @()
try {
    $net = Get-NetTCPConnection -State Listen -ErrorAction Stop
    foreach ($conn in $net) {
        $pid = $conn.OwningProcess
        $procName = ""
        try { $procName = (Get-Process -Id $pid -ErrorAction Stop).ProcessName } catch { $procName = "PID:$pid" }
        $portsList += [PSCustomObject]@{
            LocalAddress = $conn.LocalAddress
            LocalPort    = $conn.LocalPort
            Protocol     = "TCP"
            ProcessId    = $pid
            ProcessName  = $procName
        }
    }
} catch {
    Log "Get-NetTCPConnection failed: $($_.Exception.Message) - attempting netstat fallback"
    $netstat = netstat -ano | Select-String "LISTENING"
    foreach ($ln in $netstat) {
        # crude parse: extract address:port and pid
        $parts = ($ln -split "\s+") | Where-Object { $_ -ne "" }
        if ($parts.Length -ge 5) {
            $addrPort = $parts[1]
            $pid = $parts[-1]
            $port = ($addrPort -split ":")[-1]
            $portsList += [PSCustomObject]@{
                LocalAddress = $addrPort -replace ":\d+$",""
                LocalPort = [int]$port
                Protocol = "TCP"
                ProcessId = $pid
                ProcessName = "PID:$pid"
            }
        }
    }
}
# Format ports output
$portsText = "Open TCP Listening Ports:`n"
foreach ($p in $portsList | Sort-Object LocalPort) {
    $portsText += ("Port {0} ({1}) - Process: {2} (PID {3})`n" -f $p.LocalPort, $p.LocalAddress, $p.ProcessName, $p.ProcessId)
}
Log "Found $($portsList.Count) listening entries"
#endregion

#region 2) SSL Certificate extraction & 3) TLS protocol + negotiated cipher checks
Log "Attempting SSL/TLS handshakes on likely SSL ports..."
# Common ports we might test first (merge with actual listening ports)
$likelySslPorts = @()
$likelySslPorts += ($portsList | Where-Object { $_.LocalPort -in  @(443, 8443, 4443, 3389, 5986, 636, 990, 993, 995) } | Select-Object -ExpandProperty LocalPort -Unique)
# Also test all listening ports but limit to top 50 to control runtime; adjust as needed.
$allPortsToTest = ($portsList | Select-Object -ExpandProperty LocalPort -Unique) | Sort-Object
if ($allPortsToTest.Count -gt 50) {
    Log "Too many ports ($($allPortsToTest.Count)); restricting to 50 ports for handshake testing."
    $allPortsToTest = $allPortsToTest[0..49]
}
# Protocols to test (small constant T)
$protoCandidates = @(
    [System.Security.Authentication.SslProtocols]::Tls12,
    [System.Security.Authentication.SslProtocols]::Tls11,
    [System.Security.Authentication.SslProtocols]::Tls
)
# Try to include TLS13 if available in runtime
try {
    $tls13 = [System.Enum]::Parse([System.Security.Authentication.SslProtocols],"Tls13")
    if ($tls13) { $protoCandidates = @($tls13) + $protoCandidates }
} catch {}

$certResults = @()
$cipherResults = @()

# Helper to perform handshake with timeout
function Test-Handshake {
    param([int]$port, [System.Security.Authentication.SslProtocols]$protocol)
    $result = [PSCustomObject]@{Success=$false; Protocol=$protocol.ToString(); Cipher=""; Cert=$null; Error=$null}
    try {
        $client = New-Object System.Net.Sockets.TcpClient("127.0.0.1",$port)
        $ns = $client.GetStream()
        $callback = {
            param($sender,$cert,$chain,$errors)
            # allow any cert; we only want the cert object
            return $true
        }
        $ssl = New-Object System.Net.Security.SslStream($ns,$false,$callback,$null)
        # set authentication async in a job to enforce timeout
        $job = Start-Job -ScriptBlock {
            param($ssl,$protocol)
            $ssl.AuthenticateAsClient("localhost",[System.Security.Cryptography.X509Certificates.X509CertificateCollection]::new(),$protocol,$false)
            return $ssl
        } -ArgumentList ($ssl,$protocol)
        $ok = $job | Wait-Job -Timeout $HandshakeTimeoutSec
        if (-not $ok) {
            Stop-Job $job | Out-Null
            Remove-Job $job | Out-Null
            $client.Close()
            $result.Error = "Handshake timeout"
            return $result
        }
        $jobResult = Receive-Job $job
        Remove-Job $job | Out-Null

        # If succeeded, gather negotiated cipher details (if available)
        try {
            # After Authenticate, SslStream properties:
            $cipherAlg = $ssl.CipherAlgorithm
            $cipherStrength = $ssl.CipherStrength
            $protocolUsed = $ssl.SslProtocol  # negotiated
            $result.Success = $true
            $result.Cipher = ("{0} ({1} bits)" -f $cipherAlg, $cipherStrength)
            $result.Protocol = $protocolUsed.ToString()
            if ($ssl.RemoteCertificate) {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
                $result.Cert = $cert
            }
            $ssl.Close()
            $client.Close()
        } catch {
            $result.Error = "Post-handshake parse error: $($_.Exception.Message)"
            $client.Close()
        }
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

foreach ($port in $allPortsToTest) {
    foreach ($proto in $protoCandidates) {
        Log "Testing port $port with protocol $proto"
        $r = Test-Handshake -port $port -protocol $proto
        if ($r.Success) {
            # Cert capture
            if ($r.Cert -ne $null) {
                $cert = $r.Cert
                $certResults += [PSCustomObject]@{
                    Port = $port
                    Protocol = $r.Protocol
                    Subject = $cert.Subject
                    Issuer = $cert.Issuer
                    NotBefore = $cert.NotBefore
                    NotAfter  = $cert.NotAfter
                    Thumbprint = $cert.Thumbprint
                }
            }
            $cipherResults += [PSCustomObject]@{
                Port = $port
                Protocol = $r.Protocol
                Negotiated = $r.Cipher
            }
            # If handshake succeeds for one protocol on this port, optionally break to avoid duplicate captures
            break
        } else {
            Log "Port $port proto $proto : $($r.Error)"
        }
    }
}

# Format cert output
$certText = ""
if ($certResults.Count -eq 0) {
    $certText = "No TLS/SSL certificates found on tested ports."
} else {
    $certText = "Certificates found:`n"
    foreach ($c in $certResults | Sort-Object Port) {
        $certText += ("Port {0} - Protocol: {1}`n  Subject: {2}`n  Issuer: {3}`n  Valid: {4} -> {5}`n  Thumbprint: {6}`n`n" -f $c.Port, $c.Protocol, $c.Subject, $c.Issuer, $c.NotBefore, $c.NotAfter, $c.Thumbprint)
    }
}

# Format cipher output
$cipherText = ""
if ($cipherResults.Count -eq 0) {
    $cipherText = "No negotiated TLS cipher information discovered on tested ports."
} else {
    $cipherText = "Negotiated protocol + cipher (approx):`n"
    foreach ($c in $cipherResults | Sort-Object Port) {
        $cipherText += ("Port {0} - Protocol: {1} - Cipher: {2}`n" -f $c.Port, $c.Protocol, $c.Negotiated)
    }
}

#endregion

#region 4) push to NinjaOne
Log "Pushing Open Ports field..."
Set-NinjaField -fieldName $FieldPorts -value $portsText | Out-Null

Log "Pushing Certificate Info field..."
Set-NinjaField -fieldName $FieldCert -value $certText | Out-Null

Log "Pushing Cipher Info field..."
Set-NinjaField -fieldName $FieldCiphers -value $cipherText | Out-Null

Log "Completed. Log:$LogFile"
"==== Completed run: $(Get-Date -Format o) ====" | Out-File -FilePath $LogFile -Encoding utf8 -Append
#endregion

<# 
Simple local test function (run interactively to sanity-check)
> .\Ninja_Scan_SSL_and_Ports.ps1 -HandshakeTimeoutSec 3 -Verbose
#>
