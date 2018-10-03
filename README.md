## Invoke-TCPPortScan

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

