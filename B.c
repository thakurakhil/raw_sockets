
/*
    @akhi
 */

#include <pcap.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>            // struct addrinfo
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <errno.h>            // errno, perror()
 
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518
 
 void print_icmp_packet(unsigned char* , int);

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
 
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define ICMP_HDRLEN 8  // ICMP header length for echo request, excludes data
 
// Function prototypes
uint16_t checksum (uint16_t *, int);
uint16_t icmp4_checksum (struct icmp, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);


/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};
 
/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
 
/* TCP header */
typedef u_int tcp_seq;
 
struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
 
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
 
void
print_payload(const u_char *payload, int len);
 
void
print_hex_ascii_line(const u_char *payload, int len, int offset);
 
 
 
/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{
 
 int i;
 int gap;
 const u_char *ch;
 
 /* offset */
 printf("%05d   ", offset);
  
 /* hex */
 ch = payload;
 for(i = 0; i < len; i++) {
  printf("%02x ", *ch);
  ch++;
  /* print extra space after 8th byte for visual aid */
  if (i == 7)
   printf(" ");
 }
 /* print space to handle line less than 8 bytes */
 if (len < 8)
  printf(" ");
  
 /* fill hex gap with spaces if not full line */
 if (len < 16) {
  gap = 16 - len;
  for (i = 0; i < gap; i++) {
   printf("   ");
  }
 }
 printf("   ");
  
 /* ascii (if printable) */
 ch = payload;
 for(i = 0; i < len; i++) {
  if (isprint(*ch))
   printf("%c", *ch);
  else
   printf(".");
  ch++;
 }
 
 printf("\n");
 
return;
}
 

void send_back_to_a(char *destination_address)
{

  int i, status, datalen, frame_length;
  char *interface, *target;
  
  int  sd, bytes, *ip_flags;
  char  *src_ip, *dst_ip;
  
  struct icmp icmphdr;
  
  struct ip iphdr;
  void *tmp;

  uint8_t *data, *src_mac, *dst_mac, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
      unsigned char *buffer1 = (unsigned char *)malloc(65536); //Its Big!

  struct sockaddr_ll device;
  struct ifreq ifr;

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem (6);
  data = allocate_ustrmem (IP_MAXPACKET);
  dst_mac = allocate_ustrmem (6);
  ether_frame = allocate_ustrmem (IP_MAXPACKET);
  target = allocate_strmem (40);
  interface = allocate_strmem (40);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  ip_flags = allocate_intmem (4);
dst_ip = allocate_strmem (INET_ADDRSTRLEN);
  
  // Interface to send packet through.
  strcpy (interface, "eth0");

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
            print_icmp_packet(buffer1, 1048);

    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up interface name and get its MAC address.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
            print_icmp_packet(buffer1, 1048);

    return (EXIT_FAILURE);
  }
  close (sd);

  // Copy source MAC address.
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6);

  // Report source MAC address to stdout.
  printf ("MAC address for interface %s is ", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", src_mac[i]);
  }
  printf ("%02x\n", src_mac[5]);

  // Find interface index from interface name and store index in
  // struct sockaddr_ll device, which will be used as an argument of sendto().
  memset (&device, 0, sizeof (device));
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }
  printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

  // Set destination MAC address: you need to fill these out
  dst_mac[0] = 0xaa;
  dst_mac[1] = 0xaa;
  dst_mac[2] = 0xaa;
  dst_mac[3] = 0xaa;
  dst_mac[4] = 0xaa;
  dst_mac[5] = 0xaa;

  // Source IPv4 address: you need to fill this out
  strcpy (src_ip, destination_address);

  // Destination URL or IPv4 address: you need to fill this out
  strcpy (target, "11.11.11.11");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  tmp = &(ipv4->sin_addr);
  if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

  // Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6);
  device.sll_halen = 6;

  // ICMP data
  datalen = 4;
  data[3] = 't';
data[0] = 't';
  data[2] = 's';
  data[1] = 'e';
  
  // IPv4 header


  
  // Type of service (8 bits)
  iphdr.ip_tos = 0;

// Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
  iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;


  // ID sequence number (16 bits): unused, since single datagram
  iphdr.ip_id = htons (0);


  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

// Transport layer protocol (8 bits): 1 for ICMP
  iphdr.ip_p = IPPROTO_ICMP;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

// Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = 255;

  iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  
  
  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));

    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data)
  frame_length = 6 + 6 + 2 + IP4_HDRLEN + ICMP_HDRLEN + datalen;


  // ICMP header

// Message Code (8 bits): echo request
  icmphdr.icmp_code = 0;

  // Message Type (8 bits): echo request
  icmphdr.icmp_type = ICMP_ECHO;

  
  
  // Sequence Number (16 bits): starts at 0
  icmphdr.icmp_seq = htons (0);

// Identifier (16 bits): usually pid of sending process - pick a number
  icmphdr.icmp_id = htons (1000);


  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  icmphdr.icmp_cksum = icmp4_checksum (icmphdr, data, datalen);

  // Fill out ethernet frame header.


  // Destination and Source MAC addresses
  memcpy (ether_frame, dst_mac, 6);
  memcpy (ether_frame + 5+1, src_mac, 5+1);

  // Next is ethernet type code (ETH_P_IP for IPv4).
  // http://www.iana.org/assignments/ethernet-numbers
  ether_frame[13] = ETH_P_IP % 256;

ether_frame[12] = ETH_P_IP / 256;
  
  // Next is ethernet frame data (IPv4 header + ICMP header + ICMP data).

  // IPv4 header
  memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN);

  // ICMP header
  memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN);

  // ICMP data
  memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

  // Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed ");
            print_icmp_packet(buffer1, 1048);

    exit (EXIT_FAILURE);
  }

  // Send ethernet frame to socket.
  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    perror ("sendto() failed");
            print_icmp_packet(buffer1, 1048);

    exit (EXIT_FAILURE);
  }

  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (src_mac);
  free (dst_mac);
  free (data);
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (ip_flags);

}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{
    unsigned char *buffer1 = (unsigned char *)malloc(65536); //Its Big!

 
 int len_rem = len;
 int line_width = 16;   /* number of bytes per line */
 int line_len;
 int offset = 0;     /* zero-based offset counter */
 const u_char *ch = payload;
 
 if (len <= 0)
  return;
 
 /* data fits on one line */
 if (len <= line_width) {
  print_hex_ascii_line(ch, len, offset);
  return;
 }
 
 /* data spans multiple lines */
 for ( ;; ) {
  /* compute current line length */
  line_len = line_width % len_rem;
  /* print line */
  print_hex_ascii_line(ch, line_len, offset);
  /* compute total remaining */
  len_rem = len_rem - line_len;
  /* shift pointer to remaining bytes to print */
  ch = ch + line_len;
  /* add offset */
  offset = offset + line_width;
  /* check if we have line width chars or less */
  if (len_rem <= line_width) {
   /* print last line and get out */
   print_hex_ascii_line(ch, len_rem, offset);
   break;
  }
 }
 
return;
}



 
int main(int argc, char **argv)
{
 
 char *dev = NULL;   /* capture device name */
 char errbuf[PCAP_ERRBUF_SIZE];  /* error buffer */
 pcap_t *handle;    /* packet capture handle */
 
  unsigned char *buffer1 = (unsigned char *)malloc(65536); //Its Big!

 char filter_exp[] = "ip";  /* filter expression */
 struct bpf_program fp;   /* compiled filter program (expression) */
 bpf_u_int32 mask;   /* subnet mask */
 bpf_u_int32 net;   /* ip */
 int num_packets ;   /* number of packets to capture */
 
 /* check for capture device name on command-line */
 if (argc == 2) {
  dev = argv[1];
 }
 else if (argc > 3) {
  fprintf(stderr, "error: unrecognized command-line options\n\n");
 printf("Usage: %s [interface]\n", argv[0]);
 printf("\n");
 printf("Options:\n");
 printf("    interface    Listen on <interface> for packets.\n");
 printf("\n");
  exit(EXIT_FAILURE);
 }
 else {
  /* find a capture device if not specified on command-line */
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
   fprintf(stderr, "Couldn't find default device: %s\n",
       errbuf);
   exit(EXIT_FAILURE);
  }
 }
 printf("\nEnter no. of packets you want to capture: ");
        scanf("%d",&num_packets);
        printf("\nWhich kind of packets you want to capture : ");
        scanf("%s",filter_exp);
 /* get network number and mask associated with capture device */
 if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
  fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
      dev, errbuf);
  net = 0;
  mask = 0;
 }
 
 /* print capture info */
 printf("Device: %s\n", dev);
 printf("Number of packets: %d\n", num_packets);
 printf("Filter expression: %s\n", filter_exp);
 
 /* open capture device */
 handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
 if (handle == NULL) {
  fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
          print_icmp_packet(buffer1, 1048);

  exit(EXIT_FAILURE);
 }
 
 /* make sure we're capturing on an Ethernet device [2] */
 if (pcap_datalink(handle) != DLT_EN10MB) {
  fprintf(stderr, "%s is not an Ethernet\n", dev);
          print_icmp_packet(buffer1, 1048);

  exit(EXIT_FAILURE);
 }
 
 /* compile the filter expression */
 if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
  fprintf(stderr, "Couldn't parse filter %s: %s\n",
      filter_exp, pcap_geterr(handle));
          print_icmp_packet(buffer1, 1048);

  exit(EXIT_FAILURE);
 }
 
 /* apply the compiled filter */
 if (pcap_setfilter(handle, &fp) == -1) {
  fprintf(stderr, "Couldn't install filter %s: %s\n",
      filter_exp, pcap_geterr(handle));
          print_icmp_packet(buffer1, 1048);

  exit(EXIT_FAILURE);
 }
 
 /* now we can set our callback function */
 pcap_loop(handle, num_packets, got_packet, NULL);
 
 /* cleanup */
 pcap_freecode(&fp);
 pcap_close(handle);
 
 printf("\nCapture complete.\n");
 
return 0;
}


// Build IPv4 ICMP pseudo-header and call checksum function.
uint16_t icmp4_checksum (struct icmp icmphdr, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy Message Type to buf (8 bits)
  memcpy (ptr, &icmphdr.icmp_type, sizeof (icmphdr.icmp_type));
  ptr += sizeof (icmphdr.icmp_type);
  chksumlen += sizeof (icmphdr.icmp_type);

  // Copy Message Code to buf (8 bits)
  memcpy (ptr, &icmphdr.icmp_code, sizeof (icmphdr.icmp_code));
  ptr += sizeof (icmphdr.icmp_code);
  chksumlen += sizeof (icmphdr.icmp_code);

  // Copy ICMP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy Identifier to buf (16 bits)
  memcpy (ptr, &icmphdr.icmp_id, sizeof (icmphdr.icmp_id));
  ptr += sizeof (icmphdr.icmp_id);
  chksumlen += sizeof (icmphdr.icmp_id);

  // Copy Sequence Number to buf (16 bits)
  memcpy (ptr, &icmphdr.icmp_seq, sizeof (icmphdr.icmp_seq));
  ptr += sizeof (icmphdr.icmp_seq);
  chksumlen += sizeof (icmphdr.icmp_seq);

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
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

// Allocate memory for an array of chars.
char * allocate_strmem (int len)
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


/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

 static int count = 1;                   /* packet counter */
  
 /* declare pointers to packet headers */
 const struct sniff_ip *ip;              /* The IP header */
 const struct sniff_tcp *tcp;            /* The TCP header */
 const char *payload;                    /* Packet payload */
 
 int size_ip;
 int size_tcp;
 int size_payload;
  
 printf("\nPacket number %d:\n", count);
 count++;
  
 /* define ethernet header */
 const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  ethernet = (struct sniff_ethernet*)(packet);
 
 printf("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
    (unsigned)ethernet->ether_shost[0],
    (unsigned)ethernet->ether_shost[1],
    (unsigned)ethernet->ether_shost[2],
    (unsigned)ethernet->ether_shost[3],
    (unsigned)ethernet->ether_shost[4],
    (unsigned)ethernet->ether_shost[5]);
 printf("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
    (unsigned)ethernet->ether_dhost[0],
    (unsigned)ethernet->ether_dhost[1],
    (unsigned)ethernet->ether_dhost[2],
    (unsigned)ethernet->ether_dhost[3],
    (unsigned)ethernet->ether_dhost[4],
    (unsigned)ethernet->ether_dhost[5]);

 
 /* define/compute ip header offset */
 ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
 size_ip = IP_HL(ip)*4;
 if (size_ip < 20) {
  printf("   * Invalid IP header length: %u bytes\n", size_ip);
  return;
 }
 
 /* print source and destination IP addresses */
 printf("       From: %s\n", inet_ntoa(ip->ip_src));
 printf("         To: %s\n", inet_ntoa(ip->ip_dst));

if(ethernet->ether_dhost[0]==0xcc)
 {
  printf("Local packet dropped\n");
  return;
  }

 printf("Changing destination MAC address to cc:cc:cc:cc:cc:cc and sending packet\n");
 /**/



int i, status, datalen, frame_length, sendsd, recvsd, bytes, *ip_flags, timeout, trycount, trylim, done;
  char *interface, *target, *src_ip, *dst_ip, *rec_ip, *a_ip;
  struct ip send_iphdr, *recv_iphdr;
  struct icmp send_icmphdr, *recv_icmphdr;
  uint8_t *data, *src_mac, *dst_mac, *send_ether_frame, *recv_ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  struct ifreq ifr;
  struct sockaddr from;
  socklen_t fromlen;
  struct timeval wait, t1, t2;
  struct timezone tz;
  double dt;
  void *tmp;

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  data = allocate_ustrmem (IP_MAXPACKET);
  send_ether_frame = allocate_ustrmem (IP_MAXPACKET);
  recv_ether_frame = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (40);
  target = allocate_strmem (40);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);
  rec_ip = allocate_strmem (INET_ADDRSTRLEN);
  a_ip = allocate_strmem (INET_ADDRSTRLEN);
  ip_flags = allocate_intmem (4);

  // Interface to send packet through.
  strcpy (interface, "eth0");

  // Submit request for a socket descriptor to look up interface.
  // We'll use it to send packets as well, so we leave it open.
  if ((sendsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up interface name and get its MAC address.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sendsd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    //return (EXIT_FAILURE);
  }

  // Copy source MAC address.
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6);

  // Report source MAC address to stdout.
  printf ("MAC address for interface %s is ", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", src_mac[i]);
  }
  printf ("%02x\n", src_mac[5]);

  // Find interface index from interface name and store index in
  // struct sockaddr_ll device, which will be used as an argument of sendto().
  memset (&device, 0, sizeof (device));
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }
  printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

   // Set destination MAC address: you need to fill these out
  dst_mac[0] = 0xcc;
  dst_mac[1] = 0xcc;
  dst_mac[2] = 0xcc;
  dst_mac[3] = 0xcc;
  dst_mac[4] = 0xcc;
  dst_mac[5] = 0xcc;

  // Source IPv4 address: you need to fill this out
  strcpy (src_ip, "22.22.22.22");

  // Destination URL or IPv4 address: you need to fill this out
  strcpy (target, "33.33.33.33");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  tmp = &(ipv4->sin_addr);
  if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

  // Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6);
  device.sll_halen = 6;

  // ICMP data
  datalen = 4;
  data[0] = 'T';
  data[1] = 'e';
  data[2] = 's';
  data[3] = 't';

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  send_iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  send_iphdr.ip_v = 4;

  // Type of service (8 bits)
  send_iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
  send_iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

  // ID sequence number (16 bits): unused, since single datagram
  send_iphdr.ip_id = htons (0);

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  send_iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  send_iphdr.ip_ttl = 255;

  // Transport layer protocol (8 bits): 1 for ICMP
  send_iphdr.ip_p = IPPROTO_ICMP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(send_iphdr.ip_src))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(send_iphdr.ip_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  send_iphdr.ip_sum = 0;
  send_iphdr.ip_sum = checksum ((uint16_t *) &send_iphdr, IP4_HDRLEN);

  // ICMP header

  // Message Type (8 bits): echo request
  send_icmphdr.icmp_type = ICMP_ECHO;

  // Message Code (8 bits): echo request
  send_icmphdr.icmp_code = 0;

  // Identifier (16 bits): usually pid of sending process - pick a number
  send_icmphdr.icmp_id = htons (1000);

  // Sequence Number (16 bits): starts at 0
  send_icmphdr.icmp_seq = htons (0);

  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  send_icmphdr.icmp_cksum = icmp4_checksum (send_icmphdr, data, datalen);

  // Fill out ethernet frame header.

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data)
  frame_length = 6 + 6 + 2 + IP4_HDRLEN + ICMP_HDRLEN + datalen;

  // Destination and Source MAC addresses
  memcpy (send_ether_frame, dst_mac, 6);
  memcpy (send_ether_frame + 6, src_mac, 6);

  // Next is ethernet type code (ETH_P_IP for IPv4).
  // http://www.iana.org/assignments/ethernet-numbers
  send_ether_frame[12] = ETH_P_IP / 256;
  send_ether_frame[13] = ETH_P_IP % 256;

  // Next is ethernet frame data (IPv4 header + ICMP header + ICMP data).

  // IPv4 header
  memcpy (send_ether_frame + ETH_HDRLEN, &send_iphdr, IP4_HDRLEN);

  // ICMP header
  memcpy (send_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &send_icmphdr, ICMP_HDRLEN);

  // ICMP data
  memcpy (send_ether_frame + ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

  // Submit request for a raw socket descriptor to receive packets.
  if ((recvsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed to obtain a receive socket descriptor ");
    exit (EXIT_FAILURE);
  }

  // Set maximum number of tries to ping remote host before giving up.
  trylim = 3;
  trycount = 0;

  // Cast recv_iphdr as pointer to IPv4 header within received ethernet frame.
  recv_iphdr = (struct ip *) (recv_ether_frame + ETH_HDRLEN);

  // Case recv_icmphdr as pointer to ICMP header within received ethernet frame.
  recv_icmphdr = (struct icmp *) (recv_ether_frame + ETH_HDRLEN + IP4_HDRLEN);

  done = 0;
  for (;;) {

    // SEND

    // Send ethernet frame to socket.
    if ((bytes = sendto (sendsd, send_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
      perror ("sendto() failed ");
      exit (EXIT_FAILURE);
    }

    // Start timer.
    (void) gettimeofday (&t1, &tz);

    // Set time for the socket to timeout and give up waiting for a reply.
    timeout = 2;
    wait.tv_sec  = timeout;  
    wait.tv_usec = 0;
    setsockopt (recvsd, SOL_SOCKET, SO_RCVTIMEO, (char *) &wait, sizeof (struct timeval));

    // Listen for incoming ethernet frame from socket recvsd.
    // We expect an ICMP ethernet frame of the form:
    //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes)
    //     + ethernet data (IPv4 header + ICMP header)
    // Keep at it for 'timeout' seconds, or until we get an ICMP reply.

    // RECEIVE LOOP
    for (;;) {

      memset (recv_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
      memset (&from, 0, sizeof (from));
      fromlen = sizeof (from);
      if ((bytes = recvfrom (recvsd, recv_ether_frame, IP_MAXPACKET, 0, (struct sockaddr *) &from, &fromlen)) < 0) {

        status = errno;

        // Deal with error conditions first.
        if (status == EAGAIN) {  // EAGAIN = 11
          printf ("No reply within %i seconds.\n", timeout);
          trycount++;
          break;  // Break out of Receive loop.
        } else if (status == EINTR) {  // EINTR = 4
          continue;  // Something weird happened, but let's keep listening.
        } else {
          perror ("recvfrom() failed ");
          exit (EXIT_FAILURE);
        }
      }  // End of error handling conditionals.

      // Check for an IP ethernet frame, carrying ICMP echo reply. If not, ignore and keep listening.
      if ((((recv_ether_frame[12] << 8) + recv_ether_frame[13]) == ETH_P_IP) &&
         (recv_iphdr->ip_p == IPPROTO_ICMP) && (recv_icmphdr->icmp_type == ICMP_ECHOREPLY) && (recv_icmphdr->icmp_code == 0)) {

        // Stop timer and calculate how long it took to get a reply.
        (void) gettimeofday (&t2, &tz);
        dt = (double) (t2.tv_sec - t1.tv_sec) * 1000.0 + (double) (t2.tv_usec - t1.tv_usec) / 1000.0;

        // Extract source IP address from received ethernet frame.
        if (inet_ntop (AF_INET, &(recv_iphdr->ip_src.s_addr), rec_ip, INET_ADDRSTRLEN) == NULL) {
          status = errno;
          fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
          exit (EXIT_FAILURE);
        }

        // Report source IPv4 address and time for reply.
        printf ("%s  %g ms (%i bytes received)\n", rec_ip, dt, bytes);
        done = 1;
        send_back_to_a(inet_ntoa(ip->ip_dst));
        break;  // Break out of Receive loop.
      }  // End if IP ethernet frame carrying ICMP_ECHOREPLY
    }  // End of Receive loop.

    // The 'done' flag was set because an echo reply was received; break out of send loop.
    if (done == 1) {
      break;  // Break out of Send loop.
    }

    // We ran out of tries, so let's give up.
    if (trycount == trylim) {
      printf ("Recognized no echo replies from remote host after %i tries.\n", trylim);
      break;
    }

  }  // End of Send loop.

  // Close socket descriptors.
  close (sendsd);
  close (recvsd);

  // Free allocated memory.
  free (src_mac);
  free (dst_mac);
  free (data);
  free (send_ether_frame);
  free (recv_ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (rec_ip);
  free (ip_flags);




 /**/
 
  
 /* determine protocol */
 switch(ip->ip_p) {
  case IPPROTO_TCP:
   printf("   Protocol: TCP\n");
   break;
  case IPPROTO_UDP:
   printf("   Protocol: UDP\n");
   return;
  case IPPROTO_ICMP:
   printf("   Protocol: ICMP\n");
   return;
  case IPPROTO_IP:
   printf("   Protocol: IP\n");
   return;
  default:
   printf("   Protocol: unknown\n");
   return;
 }
  
 /*
  *  OK, this packet is TCP.
  */
  
 /* define/compute tcp header offset */
 tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
 size_tcp = TH_OFF(tcp)*4;
 if (size_tcp < 20) {
  printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
  return;
 }
  
 printf("   Src port: %d\n", ntohs(tcp->th_sport));
 printf("   Dst port: %d\n", ntohs(tcp->th_dport));
  
 /* define/compute tcp payload (segment) offset */
 payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
  
 /* compute tcp payload (segment) size */
 size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
  
 /*
  * Print payload data; it might be binary, so don't just
  * treat it as a string.
  */
 if (size_payload > 0) {
  printf("   Payload (%d bytes):\n", size_payload);
  print_payload(payload, size_payload);
 }
 
return;
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

// Allocate memory for an array of ints.
int *
allocate_intmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}


 void print_icmp_packet(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;

printf("got \n");
    
    struct iphdr *iph = (struct iphdr *)Buffer;
    
    iphdrlen = iph->ihl;

    iphdrlen = iphdrlen*4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);
/*
    fprintf(logfile,"\n\n--------------ICMP Packet for ping -------------\n");   

    print_ip_header(Buffer , Size);

    fprintf(logfile,"\n");

    fprintf(logfile,"ICMP Header\n");
    fprintf(logfile,"   |-Type : %d",(unsigned int)(icmph->type));

    if((unsigned int)(icmph->type) == 11) 
        fprintf(logfile,"  (TTL Expired)\n");
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) 
        fprintf(logfile,"  (ICMP Echo Reply)\n");
    fprintf(logfile,"   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile,"   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(logfile,"   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(logfile,"   |-Sequence : %d\n",ntohs(icmph->sequence));
    fprintf(logfile,"\n");

    fprintf(logfile,"IP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(logfile,"UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);

    fprintf(logfile,"Data Payload\n");  
    PrintData(Buffer + iphdrlen + sizeof icmph , (Size - sizeof icmph - iph->ihl * 4));

    fprintf(logfile,"\n###########################################################");
    */
}
