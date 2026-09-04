# Basic PowerShell TCP port scanner (Windows) using TcpClient.
# Authorized use only. Replace target IP in the usage example.
#
# Usage (PowerShell 5.1+):
#   .\port-scan-powershell.ps1 -Target 192.168.1.1
#   .\port-scan-powershell.ps1 -Target 192.168.1.1 -Ports 21,22,80,443,3306,6379
#   .\port-scan-powershell.ps1 -Target 192.168.1.1 -StartPort 1 -EndPort 1024

param(
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [int[]]$Ports,
    [int]$StartPort = 1,
    [int]$EndPort = 1024,
    [int]$TimeoutMs = 800
)

function Connect-Port {
    param([string]$HostAddr, [int]$Port, [int]$Timeout)

    $client = New-Object System.Net.Sockets.TcpClient
    $beginConnect = $client.BeginConnect($HostAddr, $Port, $null, $null)
    $done = $beginConnect.AsyncWaitHandle.WaitOne($Timeout, $false)
    if ($done -and $client.Connected) {
        # Service name guess by port
        $service = switch ($Port) {
            21 { "FTP" }; 22 { "SSH" }; 23 { "Telnet" }; 25 { "SMTP" }; 53 { "DNS" }
            80 { "HTTP" }; 110 { "POP3" }; 135 { "MSRPC" }; 139 { "NetBIOS" }; 143 { "IMAP" }
            443 { "HTTPS" }; 445 { "SMB" }; 873 { "rsync" }; 1433 { "MSSQL" }; 1521 { "Oracle" }
            2049 { "NFS" }; 2375 { "Docker" }; 3000 { "Grafana" }; 3306 { "MySQL" }
            3389 { "RDP" }; 4369 { "RabbitMQ" }; 5432 { "PostgreSQL" }; 5601 { "Kibana" }
            5900 { "VNC" }; 5985 { "WinRM" }; 5986 { "WinRM-HTTPS" }; 6379 { "Redis" }
            7001 { "WebLogic" }; 8080 { "HTTP-alt" }; 8443 { "HTTPS-alt" }; 8888 { "Proxy" }
            9000 { "PHP-FPM" }; 9090 { "Prometheus" }; 9200 { "Elasticsearch" }
            10000 { "Webmin" }; 11211 { "Memcached" }; 27017 { "MongoDB" }; 61616 { "ActiveMQ" }
            default { "unknown" }
        }
        $client.Close()
        return ("[+] OPEN  {0}:{1,-6} {2}" -f $HostAddr, $Port, $service)
    }
    $client.Close()
    return $null
}

# if -Ports given use it, else build range
if ($null -eq $Ports -or $Ports.Count -eq 0) {
    $Ports = @($StartPort..$EndPort)
}

Write-Host "[*] scanning $Target ($($Ports.Count) ports) ..."

$results = foreach ($Port in $Ports) {
    $r = Connect-Port -HostAddr $Target -Port $Port -Timeout $TimeoutMs
    if ($r) { Write-Host $r }
}

Write-Host "[*] finished."