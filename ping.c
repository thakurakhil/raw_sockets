/*
    @akhi
 */


#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <unistd.h>
#include <netinet/ip.h>
 
typedef unsigned short int u16;
typedef unsigned char u8;
 
void help(const char *p);
unsigned short in_cksum(unsigned short *ptr, int nbytes);
void print_icmp_packet(unsigned char* , int);
 
int main(int argc, char **argv)
{
    if (argc < 3) 
    {
        printf("usage: %s <source IP> <destination IP> [payload size]\n", argv[0]);
        exit(0);
    }
     
    unsigned long daddr;
    unsigned long saddr;
    int payload_size = 0;
    int sent, sent_size;
     
    unsigned char *buffer1 = (unsigned char *)malloc(65536); //Its Big!

    daddr = inet_addr(argv[2]);
    saddr = inet_addr(argv[1]);
    

    if (argc >= 4)
    {
        payload_size = atoi(argv[3]);
    }
     
    //Raw socket - if you use IPPROTO_ICMP, then kernel will fill in the correct ICMP header checksum, if IPPROTO_RAW, then it wont
    int sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
     
    if (!(sockfd >= 0))
    {
        perror("could not create the socket");
        return (0);
    }
     
    int on = 1;
     
    // We shall provide IP headers
    if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1) 
    {
        perror("setsockopt");
        print_icmp_packet(buffer1, 1048);
        return (0);
    }
     
    //allow socket to send datagrams to broadcast addresses
    if (setsockopt (sockfd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof (on)) == -1) 
    {
        perror("setsockopt");
        print_icmp_packet(buffer1, 1048);
        return (0);
    }   
     
    //Calculate total packet size
    int packet_size = sizeof (struct iphdr) + sizeof (struct icmphdr) + payload_size;
    char *packet = (char *) malloc (packet_size);
                    
    if (!packet) 
    {
        perror("out of memory");
        print_icmp_packet(buffer1, 1048);
        close(sockfd);
        return (0);
    }
    
    //zero out the packet buffer
    memset (packet, 0, packet_size);
  
    //ip header
    struct iphdr *ip = (struct iphdr *) packet;
    struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof (struct iphdr));
     
    
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons (packet_size);
    ip->tos = 0;
    ip->id = rand ();
    ip->ttl = 255;
    ip->frag_off = 0;
    ip->protocol = IPPROTO_ICMP;
    ip->daddr = daddr;
    ip->saddr = saddr;
    //ip->check = in_cksum ((u16 *) ip, sizeof (struct iphdr));
 
    icmp->type = ICMP_ECHO;
    icmp->un.echo.sequence = rand();
    icmp->checksum = 0;
    icmp->code = 0;
    icmp->un.echo.id = rand();
    
int number = 0;
    
    //checksum
     
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = daddr;
    memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
 
    
    while (1)
    {
        memset(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), rand() % 255, payload_size);
         
        //recalculate the icmp header checksum since we are filling the payload with random characters everytime
        icmp->checksum = 0;
        icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + payload_size);
         
        if ( (sent_size = sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
        {
            perror("send failed\n");
            print_icmp_packet(buffer1, 1048);
            break;
        }
        number++;
        
        printf("%d packets sent\r", number);

        fflush(stdout);
         
        usleep(1000000);  //microseconds
        
        if(number==10)
            break;
    }
     
    free(packet);
    close(sockfd);
     
    return (0);
}
 
/*
    Function calculate checksum
*/
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
    register long sum;
    u_short oddbyte;
    register u_short answer;
 
    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
 
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) & oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }
 
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
 
    return (answer);
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
