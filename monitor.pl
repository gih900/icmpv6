#!/usr/bin/perl
# simple monitor of IPv6 DNS UDP packets
# the filter is looking for ann IPv6 UDP and IPv6 Frags on interface eth0
#
$tcp = "tcpdump -i igb0 -n  -w 'capture.pcap' '((ip6[6:1]=44) or (port 53) or ((ip[6:2] > 0) and (not ip[6] = 64)))'" ;
$cmd = $tcp ;
#$cmd = "$tcp  | ./read_pcap.pl" ;
print("$cmd\n") ;
system($cmd) ;

