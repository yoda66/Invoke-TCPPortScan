
function Invoke-TCPPortScan {
<#
.SYNOPSIS

Perform a full TCP connection scan to the destination hostname, or to
'open.zorinaq.com' if that destination is not supplied.

Author: Joff Thyer, April 2014

.DESCRIPTION

TCP-Portscan is designed to perform a full TCP connection scan to the destination
hostname using either a port range of top X number of popular TCP ports.  The top
popular port list is derived from NMAP's services using the frequrency measurements
that appear in this file.  If the top X number of popular ports is not the desired
behavior, you can specify a minimum and maximum port number within which a range of
ports will be scanned.  By default, a random delay between 50 and 200 milliseconds
is added in order to assist in avoiding detection.  Also by default, if the hostname
is not specified then 'allports.exposed' will be used as a default.   The 'open.zorinaq.com'
site responds to all TCP ports will the text of 'woot woot' if an HTTP request is sent,
but more to the point, all ports are considered open.

.PARAMETER Hostname

If provided, the hostname will be looked up and the resulting IP address used
as the IP address to be scanned.  If not provided, then the default hostname
of 'open.zorinaq.com' will be used.

.PARAMETER MinPort

Specify the minimum port number in a range of ports to be scanned.

.PARAMETER MaxPort

Specify the maximum port number in a range of ports to be scanned.

.PARAMETER TopPorts

Specify the number of popular ports which you would like to be scanned.  Up to
128 ports may be specified.

.PARAMETER Timeout

Specify the TCP connection timeout in the range of 10 - 10000 milliseconds.

.PARAMETER NoRandomDelay

Disable the random delay between connection attempts.

#>

    param(  [String]$Hostname = 'allports.exposed',
            [ValidateRange(1,65535)][Int]$MinPort = 1,
            [ValidateRange(1,65535)][Int]$MaxPort = 1,
            [ValidateRange(1,128)][Int]$TopPorts = 32,
            [ValidateRange(10,10000)][Int]$Timeout = 800,
            [switch]$NoRandomDelay = $false )

    $resolved = [System.Net.Dns]::GetHostByName($Hostname)
    $ip = $resolved.AddressList[0].IPAddressToString

    # TopN port collection derived from NMAP project
    $tcp_top128 =  80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, `
135, 3306, 8080, 1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, `
1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, `
8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, `
5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, `
2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, `
144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, `
3986, 13, 1029, 9, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, `
119, 37, 1000, 3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, `
6004, 1801, 19, 8031, 1041, 255, 3703, 17, 808, 3689, 1031, 1071, `
5901, 9102, 9000, 2105, 636, 1038, 2601, 7000

    $report = @()
    if ($MaxPort -gt 1 -and $MinPort -lt $MaxPort) {
        $ports = $MinPort..$MaxPort
        Write-Host -NoNewline "[*] Scanning $Hostname ($ip), port range $MinPort -> $MaxPort : "
    }
    elseif ($MaxPort -lt $MinPort) {
        Throw "Are you out of your mind?  Port range cannot go negative."
    }
    else {
        $ports = $tcp_top128[1..$TopPorts]
        Write-Host -NoNewline "[*] Scanning $Hostname ($ip), top $TopPorts popular ports : "
    }
    
    $total = 0
    $tcp_count = 0
    foreach ($port in Get-Random -input $ports -count $ports.Count) {
        if (![Math]::Floor($total % ($ports.Count / 10))) {
            Write-Host -NoNewline "."
        }
        $total += 1
        $temp = "" | Select Address, Port, Proto, Status, Banner
        $temp.Proto = "tcp"
        $temp.Port = $port
        $temp.Address = $ip
        $tcp = new-Object system.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($ip,$port,$null,$null)
        $wait = $connect.AsyncWaitHandle.WaitOne($Timeout,$false)
        if (!$wait) {
            $error.clear()
            $tcp.close()
            $temp.Status = "closed"
        }
        else {
            try {
                $tcp.EndConnect($connect)
                $tcp.Close()
                $temp.Status = "open"
                $tcp_count += 1
            }
            catch {
                $temp.Status = "reset"
            }
        }
        $report += $temp

        # add random delay if we want it
        if (!$NoRandomDelay) {
            $sleeptime = Get-Random -Minimum 50 -Maximum 200
            Start-Sleep -Milliseconds $sleeptime
        }
    }
    Write-Host
    $columns = @{l='IP-Address';e={$_.Address}; w=15; a="left"},@{l='Proto';e={$_.Proto};w=5;a="right"},@{l='Port';e={$_.Port}; w=5; a="right"},@{l='Status';e={$_.Status}; w=4; a="right"}
    $report | where {$_.Status -eq "open"} | Sort-Object Port | Format-Table $columns -AutoSize
    Write-Output "[*] $tcp_count out of $total scanned ports are open!"
}
