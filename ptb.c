// ptb.c
//
// This code is based on icmp6_ll.c (http://www.pdbuchan.com/rawsock/icmp6_ll.c)
// the header from icmp6_ll.c reads:
//
/*  Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
//
// Utility that synthesises ICMPv6 PTB messages
//
// The utility uses libpcap to pull in candidate V6 packets
// to respond to - if the packet is larger than 1280 then the
// routing synthesis and sends an ICMPv6 PTB message
//
// the utility uses raw ether sockets and to initialise this
// it listens for RA messages to load the router next hop
// MAC address to perform the ther framing
//
// linux debian build:
//   cc -o ptb ptb.c -lpcap 
//
// Geoff Huston, APNIC, 2018
//
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <bits/socket.h>
#include <pcap.h>
#include <errno.h>
#include <time.h>

typedef struct _pktinfo6 pktinfo6;
struct _pktinfo6 {
  struct in6_addr ipi6_addr;
  int ipi6_ifindex;
  };

//
// this is the pcap filter for candidate packets
// this is configured to look for IPv6 UDP DNS responses
//

#define FILTER "src port 53 and udp and ip6"


//
// this is the device to work from
//

#define DEVICE "eth0"


//
// this is the new MTU to advertise
//

#define MTU 1280


//
// packet frame constants
//

#define HEADER_6 40
#define HEADER_ICMP_PTB 48
#define ETH_HDRLEN 14
#define IP6_HDRLEN 40
#define ICMP_HDRLEN 8

//
// simplified ipv6 packet
//

struct ip6_pkt { 
  uint8_t ip6_version ; 
  uint8_t ip6_flowbits[3]; 
  uint16_t ip6_length; 
  uint8_t ip6_nxthdr; 
  uint8_t ip6_hoplim; 
 
  uint16_t ip6_src[8]; 
  uint16_t ip6_dst[8]; 
  char ip6_payload[1460] ; 
  }; 
 
//
// Global Variables
//

int dst_mac_set = 0 ;
uint8_t dst_mac[6] ;
uint8_t src_mac[6];
int sd ;
struct sockaddr_ll device; 
struct ifreq ifr ;
uint8_t *data, *ether_frame ;
char *interface = DEVICE ;
char *target, *src_ip, *dst_ip ;
int frame_length ;
char *filter ;


// default Ethernet snap length (maximum bytes per packet to capture)
#define SNAP_LEN 1518 
 
// ethernet headers are 14 bytes
#define SIZE_ETHERNET 14 
 

//
// Function prototypes
//

static void *find_ancillary (struct msghdr *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);



/******************************************************************* 
 * 
 * ra_mac
 *
 * get the MAC address of the local router (needed for the IPv6
 * raw IP packet interface) 
 */ 
 

uint8_t *
ra_mac()
{
  int i, status, sd, on, ifindex, hoplimit;
  struct nd_router_advert *ra;
  uint8_t *inpack;
  int len;
  struct msghdr msghdr;
  struct iovec iov[2];
  uint8_t *opt, *pkt;
  char *destination;
  struct in6_addr dst;
  int rcv_ifindex;
  struct ifreq ifr;

  // Allocate memory for various arrays.
  inpack = allocate_ustrmem (IP_MAXPACKET);
  destination = allocate_strmem (INET6_ADDRSTRLEN);

  // Prepare msghdr for recvmsg().
  memset (&msghdr, 0, sizeof (msghdr));
  msghdr.msg_name = NULL;
  msghdr.msg_namelen = 0;
  memset (&iov, 0, sizeof (iov));
  iov[0].iov_base = (uint8_t *) inpack;
  iov[0].iov_len = IP_MAXPACKET;
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 1;

  msghdr.msg_control = allocate_ustrmem (IP_MAXPACKET);
  msghdr.msg_controllen = IP_MAXPACKET * sizeof (uint8_t);

  // Request a socket descriptor sd.
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
    perror ("Failed to get socket descriptor ");
    exit (EXIT_FAILURE);
    }

  // Set flag so we receive hop limit from recvmsg.
  on = 1;
  if ((status = setsockopt (sd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof (on))) < 0) {
    perror ("setsockopt to IPV6_RECVHOPLIMIT failed ");
    exit (EXIT_FAILURE);
    }

  // Set flag so we receive destination address from recvmsg.
  on = 1;
  if ((status = setsockopt (sd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof (on))) < 0) {
    perror ("setsockopt to IPV6_RECVPKTINFO failed ");
    exit (EXIT_FAILURE);
    }

  //printf("Interface: %s\n",interface);

  // Obtain MAC address of this node.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    exit (EXIT_FAILURE);
  }

  // Retrieve interface index of this node.
  if ((ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
    }
  // printf ("\nOn this node, index for interface %s is %i\n", interface, ifindex);

  // Bind socket to interface of this node.
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof (ifr)) < 0) {
    perror ("SO_BINDTODEVICE failed");
    exit (EXIT_FAILURE);
  }

  // Listen for incoming message from socket sd.
  // Keep at it until we get a router advertisement.
  ra = (struct nd_router_advert *) inpack;
  while (ra->nd_ra_hdr.icmp6_type != ND_ROUTER_ADVERT) {
    if ((len = recvmsg (sd, &msghdr, 0)) < 0) {
      perror ("recvmsg failed ");
      exit (EXIT_FAILURE);
    }
  }

  // Ancillary data
  // printf ("\nIPv6 header data:\n");
  opt = find_ancillary (&msghdr, IPV6_HOPLIMIT);
  if (opt == NULL) {
    fprintf (stderr, "Unknown hop limit\n");
    exit (EXIT_FAILURE);
  }
  hoplimit = *(int *) opt;
  // printf ("Hop limit: %i\n", hoplimit);

  opt = find_ancillary (&msghdr, IPV6_PKTINFO);
  if (opt == NULL) {
    fprintf (stderr, "Unkown destination address\n");
    exit (EXIT_FAILURE);
    }
  memset (&dst, 0, sizeof (dst));
  dst = ((pktinfo6 *) opt)->ipi6_addr;
  if (inet_ntop (AF_INET6, &dst, destination, INET6_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
    }
  //printf ("Destination address: %s\n", destination);

  rcv_ifindex = ((pktinfo6 *) opt)->ipi6_ifindex;
  //printf ("Destination interface index: %i\n", rcv_ifindex);

  // ICMPv6 header and options data
  // printf ("\nICMPv6 header data:\n");
  // printf ("Type (134 = router advertisement): %u\n", ra->nd_ra_hdr.icmp6_type);
  // printf ("Code: %u\n", ra->nd_ra_hdr.icmp6_code);
  // printf ("Checksum: %x\n", ntohs (ra->nd_ra_hdr.icmp6_cksum));
  // printf ("Hop limit recommended by this router (0 is no recommendation): %u\n", ra->nd_ra_curhoplimit);
  // printf ("Managed address configuration flag: %u\n", ra->nd_ra_flags_reserved >> 7);
  // printf ("Other stateful configuration flag: %u\n", (ra->nd_ra_flags_reserved >> 6) & 1);
  // printf ("Mobile home agent flag: %u\n", (ra->nd_ra_flags_reserved >> 5) & 1);
  // printf ("Router lifetime as default router (s): %u\n", ntohs (ra->nd_ra_router_lifetime));
  // printf ("Reachable time (ms): %u\n", ntohl (ra->nd_ra_reachable));
  // printf ("Retransmission time (ms): %u\n", ntohl (ra->nd_ra_retransmit)); 

  // printf ("\nOptions:\n");  // Contents here are consistent with ra6.c, but others are possible

  pkt = (uint8_t *) inpack;

  // printf ("Type: %u\n", pkt[sizeof (struct nd_router_advert)]);
  // printf ("Length: %u (units of 8 octets)\n", pkt[sizeof (struct nd_router_advert) + 1]);
  // printf ("MAC address: ");

  for (i=2; i<=7; i++) {
    dst_mac[i-2] = pkt[sizeof (struct nd_router_advert) + i];
    }
  //  printf ("%02x:", pkt[sizeof (struct nd_router_advert) + i]);
  //  }
  //printf ("%02x\n", pkt[sizeof (struct nd_router_advert) + 7]);

  close (sd);

  return (&dst_mac[0]);
}

static void *
find_ancillary (struct msghdr *msg, int cmsg_type)
{
  struct cmsghdr *cmsg = NULL;

  for (cmsg = CMSG_FIRSTHDR (msg); cmsg != NULL; cmsg = CMSG_NXTHDR (msg, cmsg)) {
    if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == cmsg_type)) {
      return (CMSG_DATA (cmsg));
    }
  }

  return (NULL);
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}


// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
//

uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Build IPv6 ICMP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t
icmp6_checksum (struct ip6_hdr *iphdr, struct icmp6_hdr *icmp6hdr, int len)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &(iphdr->ip6_src.s6_addr), sizeof (iphdr->ip6_src.s6_addr));
  ptr += sizeof (iphdr->ip6_src);
  chksumlen += sizeof (iphdr->ip6_src);

  //  printf("src chksumlen=%d\n",chksumlen) ;

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &(iphdr->ip6_dst.s6_addr), sizeof (iphdr->ip6_dst.s6_addr));
  ptr += sizeof (iphdr->ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr->ip6_dst.s6_addr);

  // printf("dst chksumlen=%d\n",chksumlen) ;

  // Copy Upper Layer Packet length into buf (32 bits).
  // Should not be greater than 65535 (i.e., 2 bytes).
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 520 / 256;
  ptr++;
  *ptr = 520 % 256;
  ptr++;
  chksumlen += 4;

  // printf("len=%d chksumlen=%d\n",520,chksumlen) ;

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &(iphdr->ip6_nxt), sizeof (iphdr->ip6_nxt));
  ptr += sizeof (iphdr->ip6_nxt);
  chksumlen += sizeof (iphdr->ip6_nxt);

  // printf("nxt chksumlen=%d\n",chksumlen) ;

  // Copy ICMPv6 type to buf (8 bits)
  memcpy (ptr, icmp6hdr, len);
  ptr += len;
  chksumlen += len;

  // printf("payload chksumlen=%d\n",chksumlen) ;

  // Pad to the next 16-bit boundary
  for (i=0; i < len%2; i++, ptr++) {
    *ptr = 0;
    ptr += 1;
    chksumlen += 1;
    }

  return checksum ((uint16_t *) buf, chksumlen);
}


void
open_raw_socket()
{
  ra_mac();

  // Allocate memory for various arrays. 
  data = allocate_ustrmem (IP_MAXPACKET); 
  ether_frame = allocate_ustrmem (IP_MAXPACKET); 
  interface = allocate_strmem (40); 
  target = allocate_strmem (INET6_ADDRSTRLEN); 
  src_ip = allocate_strmem (INET6_ADDRSTRLEN); 
  dst_ip = allocate_strmem (INET6_ADDRSTRLEN); 

  // Interface to send packet through. 
  strcpy (interface, DEVICE); 
 
  // Submit request for a socket descriptor to look up interface. 
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) { 
    perror ("socket() failed to get socket descriptor for using ioctl() "); 
    exit (EXIT_FAILURE); 
    } 
 
  // Use ioctl() to look up interface name and get its MAC address. 
  memset (&ifr, 0, sizeof (ifr)); 
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface); 
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) { 
    perror ("ioctl() failed to get source MAC address "); 
    exit (EXIT_FAILURE); 
    } 
  close (sd); 
 
  // Copy source MAC address into src_mac 
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t)); 
 
  // Report source MAC address to stdout. 
  //printf ("MAC address for interface %s is ", interface); 
  //for (i=0; i<5; i++) { 
  //  printf ("%02x:", src_mac[i]); 
  //} 
  //printf ("%02x\n", src_mac[5]); 
 
  // Find interface index from interface name and store index in 
  // struct sockaddr_ll device, which will be used as an argument of sendto(). 
  memset (&device, 0, sizeof (device)); 
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) { 
    perror ("if_nametoindex() failed to obtain interface index "); 
    exit (EXIT_FAILURE); 
    } 
  //printf ("Index for interface %s is %i\n", interface, device.sll_ifindex); 
 

  // Fill out sockaddr_ll. 
  device.sll_family = AF_PACKET; 
  memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t)); 
  device.sll_halen = 6; 
 
  // Submit request for a raw socket descriptor. 
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) { 
    perror ("socket() failed "); 
    exit (EXIT_FAILURE); 
    }
  return;
  } 


/****************************************************** 
* respond 
* 
* generate an ICMP6 PTB response 
* 
*/ 
 
int  
respond_ptb(struct ip6_pkt *p)   
{  
  char out_packet_buffer[1500] ;  
  int n;
  char *inpp ;  
  struct ip6_pkt *outp ;  
  struct icmp6_hdr *icmp_hdr ;  
  struct ip6_hdr *iphdr ;

  uint32_t p_length ;  
  uint32_t type ;  
  struct sockaddr_in6 remote;  
  int sock, optval;  
  int j ;  
  int ret ;  
  struct in6_addr *src, *dst ;  
  char src_address[256]; 
  char dst_address[256]; 
  uint8_t *data ;
  int bytes ;
  int datalen ;

    
  inpp = (char *) p ;  
  outp = (struct ip6_pkt *) out_packet_buffer ;  
    
  // IPv6 header 
  iphdr = (struct ip6_hdr *) &out_packet_buffer[0] ;  

  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits) 
  iphdr->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0); 
 
  // Payload length (16 bits): 8 + 512
  iphdr->ip6_plen = htons (520); 

  // Next header (8 bits): 58 for ICMP 
  iphdr->ip6_nxt = IPPROTO_ICMPV6; 
 
  // Hop limit (8 bits): default to maximum value 
  iphdr->ip6_hops = 255; 
  
  // copy src address of the incoming packet to dst of ICMP PTB outgoing packet
  bcopy(&inpp[8],&out_packet_buffer[24],16) ;  
 
  // copy dst address of the incoming packet to src of ICMP PTB outcoing packet
  bcopy(&inpp[24],&out_packet_buffer[8],16) ;  

  // now set the interface ID of the src field to some random value
  for (n = 0 ; n < 4 ; ++n) {
    outp->ip6_src[4+n] = rand() % 65536 ;
    }

  // assemble the icmp packet
  // ICMP6 PTB is TYPE=2 CODE=0, MTU is #defined MTU val

  icmp_hdr = (struct icmp6_hdr *) &out_packet_buffer[40] ;  
  icmp_hdr->icmp6_type = ICMP6_PACKET_TOO_BIG;  
  icmp_hdr->icmp6_code = 0;  
  icmp_hdr->icmp6_mtu = htonl(MTU) ;  


  // drop the first 512 bytes of the incoming packet into the ICMP payload

  bcopy(inpp,&out_packet_buffer[48],512) ;  
  data = &out_packet_buffer[48] ;
  datalen = 512 ;

  // ICMP header checksum (16 bits): set to 0 when calculating checksum 
  icmp_hdr->icmp6_cksum = 0; 
  icmp_hdr->icmp6_cksum = icmp6_checksum (iphdr, icmp_hdr, 520); 

 
  // Fill out ethernet frame header. 
  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data) 
  frame_length = 6 + 6 + 2 + 40 + 8 + 512; 
 
  // Destination and Source MAC addresses 
  memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t)); 
  memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t)); 
 
  // Next is ethernet type code (ETH_P_IPV6 for IPv6). 
  // http://www.iana.org/assignments/ethernet-numbers 
  ether_frame[12] = ETH_P_IPV6 / 256; 
  ether_frame[13] = ETH_P_IPV6 % 256; 
 
  // Next is ethernet frame data (IPv6 header + ICMP header + ICMP data). 
 
  // IPv6 header 
  memcpy (ether_frame + ETH_HDRLEN, iphdr, 560); 
 
  inet_ntop(AF_INET6,&out_packet_buffer[24],dst_address,256);
  printf("  **-> ICMP Send packet %s\n",dst_address) ;
 
  // Send ethernet frame to socket. 

  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) { 
    perror ("sendto() failed"); 
    exit (EXIT_FAILURE); 
    } 
 
}


/****************************************************** 
 * 
 * packet dispatcher 
 *
 */ 
 
void 
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{ 
  struct ip6_hdr *ip6;                 /* The IPv6 header */ 
  int size_ip;                         /* payload length */
  char address[256] ;
         
  /* point to the IP6 header within the Etherframe */ 
  ip6 = (struct ip6_hdr*)(packet + SIZE_ETHERNET); 
  size_ip = ntohs(ip6->ip6_plen) ; 


  inet_ntop(AF_INET6,ip6->ip6_src.s6_addr,address,256) ;
  printf("* %s (%d)\n",address,size_ip) ;
  if (size_ip <= 1240) { 
    return; 
    } 
         

  /* at this point we canconstruct a ICMP6 PTB response */ 
  respond_ptb((struct ip6_pkt *) ip6) ; 
 
  return; 
} 
 
void
usage() {
  fprintf(stderr,"Usage: ptb [-i device] [-m router_mac_addr] [-a DNS_server_ipv6_address]\n") ;
  exit(1) ;
}


/*******************************************************
 *
 * main
 *
 * Set up a pcap filter, open a RAW IPv6 socket and then 
 * respond to large DNS responses with an ICMP6 PTB packet
 *
 */

int
main (int argc, char **argv) {
  int i ;
  pcap_t *handle ;                           /* packet capture handle */
  char errbuff[PCAP_ERRBUF_SIZE] ;          /* error buffer */ 
  struct bpf_program fp;                    /* The compiled filter expression */      
  char *filter_exp = FILTER ;               /* The filter expression */       
  char *dev = DEVICE ;                      /* pcap device */
  bpf_u_int32 net = PCAP_NETMASK_UNKNOWN ;
  time_t t;
  int tlen, ch ;
  struct in6_addr ip6_addr;
  char target[INET_ADDRSTRLEN+1];
  int status ;

  while (((ch = getopt(argc,argv, "m:i:a:"))) != -1) {
    switch(ch) {
      case 'i':
        dev = strdup(optarg) ;
        break ;
      case 'm':
	if (sscanf(optarg, "%x:%x:%x:%x:%x:%x", &dst_mac[0], &dst_mac[1], &dst_mac[2], &dst_mac[3], &dst_mac[4], &dst_mac[5]) != 6) {
          fprintf(stderr,"%s not a MAC address\n",optarg) ;
          exit(1) ;
	  }
	break;
      case 'a':
        if (!inet_pton(AF_INET6,optarg,&ip6_addr)) {
          status = errno;
          fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
          exit (EXIT_FAILURE);
          }
        if (inet_ntop (AF_INET6, &ip6_addr, target, INET6_ADDRSTRLEN) == NULL) {
          status = errno;
          fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
          exit (EXIT_FAILURE);
          }
        tlen = strlen(FILTER) + 10 + strlen(target) ;
	filter = malloc(tlen) ;
        sprintf(filter,"%s and host %s",FILTER,target) ;
        break ;
      default:
        usage() ;
      }
    }   
  argc -= optind;
  argv += optind;
  /* Intializes random number generator */
  srand((unsigned) time(&t));

  /* open capture device */   
  if ((handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuff)) == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuff); 
    exit(EXIT_FAILURE) ; 
    }     
 
  /* compile the filter expression */ 
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {              
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle)); 
    exit(EXIT_FAILURE) ; 
    }     
 
  if (pcap_setfilter(handle, &fp) == -1) {                
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle)); 
    exit(EXIT_FAILURE) ; 
    } 
 
  /* open the raw socket */ 
  open_raw_socket() ; 


  printf("Ready\n") ;
 
  /* set up the packet cpature in an infinite loop */ 
  pcap_loop(handle, -1, got_packet, NULL) ; 
 
  /* Close the session (not executed)*/ 
  pcap_close(handle); 

  /* Close the socket (not executed)*/ 
  close(sd) ;

  return(0); 
  }
