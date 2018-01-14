# icmpv6-ptb
set of routines to perform queries to the root servers and generate ICMPv6 PTB control messages

ptb:	A raw socket IPv6 routine that will generate ICMPv6 PTB messages upon receipt
        of IPv6 UDP DNS packets with IPv6 payload size (in the Ipv6 header)  greater 
        than 1240 octets. 

any.pl:	A Perl script that performs a query "dig . ANY" in IPv4 and Ipv6 in both UDP and TCP
	in both IPv4 and IPv6. It will query all 13 root servers, sleep for 2 seconds and
        loop.

query.pl: A Perl script that performs a query in IPv4 and Ipv6 in both UDP and TCP
	in both IPv4 and IPv6. It will query all 13 root servers, sleep for 2 seconds and
        loop. The query name is the longest possible name allowed in the DNS and the response
	is intended to be a DNSSEC-signed NXDOMAIN response. The query name includes a random
        generated component to prevent cached responses.

monitor.pl: A perl script that will run a tcpdump IPv6 packet capture against responses from the
	root servers.

read_pcap.pl: A pcap reading routine that identifies fragmented packets, DNS truncated packets and 
	unfragemented packets

root-filter: A tcpfump filter expression to capture packets to/from root servers

root-ips: list of IPv4 and IPv6 addresses of root servers




