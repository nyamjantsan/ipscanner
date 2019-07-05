#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/signal.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#define DEFDATALEN      56
#define MAXIPLEN        60
#define MAXICMPLEN      76
 
static char *hostname = NULL;
 
static int in_cksum(unsigned short *buf, int sz)
{
  int nleft = sz;
  int sum = 0;
  unsigned short *w = buf;
  unsigned short ans = 0;
   
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  } 
if (nleft == 1) {
    *(unsigned char *) (&ans) = *(unsigned char *) w;
    sum += ans;
  }
   
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  ans = ~sum;
  return (ans);
}
 /* Ping function is using ICMP protocol */
static void ping(const char *host)
{
  struct hostent *h;
  struct sockaddr_in pingaddr;
  struct icmp *pkt;
  int pingsock, c;
  char packet[DEFDATALEN + MAXIPLEN + MAXICMPLEN];
   
  if ((pingsock = socket(AF_INET, SOCK_RAW, 1)) < 0) {       
    perror("ping: creating a raw socket");
    exit(1);
  }
   
 
  setuid(getuid());
   
  memset(&pingaddr, 0, sizeof(struct sockaddr_in)); 
  pingaddr.sin_family = AF_INET;
  if (!(h = gethostbyname(host))) {
    fprintf(stderr, "ping: unknown host %s\n", host);
    exit(1);
  }
  memcpy(&pingaddr.sin_addr, h->h_addr, sizeof(pingaddr.sin_addr));
  hostname = h->h_name;
   
  pkt = (struct icmp *) packet;
  memset(pkt, 0, sizeof(packet));
  pkt->icmp_type = ICMP_ECHO;
  pkt->icmp_cksum = in_cksum((unsigned short *) pkt, sizeof(packet));
   
  c = sendto(pingsock, packet, sizeof(packet), 0,
             (struct sockaddr *) &pingaddr, sizeof(struct sockaddr_in));
   
  if (c < 0 || c != sizeof(packet)) {
    if (c < 0)
      perror("ping: sendto");
    fprintf(stderr, "ping: write incomplete\n");
    exit(1);
  }
   
 /* listen replies */
  while (1) {
    struct sockaddr_in from;
    size_t fromlen = sizeof(from);
     
    if ((c = recvfrom(pingsock, packet, sizeof(packet), 0,
                      (struct sockaddr *) &from, &fromlen)) < 0) {
      if (errno == EINTR)
        continue;
      perror("ping: recvfrom"); 
 continue;
      perror("ping: recvfrom");
      continue;
    }
    if (c >= 76) {                   
      struct iphdr *iphdr = (struct iphdr *) packet;
       
      pkt = (struct icmp *) (packet + (iphdr->ihl << 2));      
      unsigned int x_hours=0;
	unsigned int x_minutes=0;
	unsigned int x_seconds=0;
	unsigned int x_milliseconds=0;
	unsigned int totaltime=0,count_down_time_in_secs=0,time_left=0;

	clock_t x_startTime,x_countTime;
	count_down_time_in_secs=3;  

 
    x_startTime=clock(); 
    time_left=count_down_time_in_secs-x_seconds;  

	while (time_left>0) 
	{
		x_countTime=clock(); 
		x_milliseconds=x_countTime-x_startTime;
		x_seconds=(x_milliseconds/(CLOCKS_PER_SEC))-(x_minutes*60);
		x_minutes=(x_milliseconds/(CLOCKS_PER_SEC))/60;
		x_hours=x_minutes/60;


	 

		time_left=count_down_time_in_secs-x_seconds;
	}
      if (pkt->icmp_type == ICMP_ECHOREPLY)
        break;
	else {
		printf("*** %s ---offline--- ***\n", hostname);
	  return;
	}
    }
  }
  printf("*** %s ---online--- ***\n", hostname);
  return;
}
 
int main ()
{	
    char ipfull[32];
    char ipbuffer[50]; 
    char buffstr[BUFSIZ];
    char startiparr[4];
    char endiparr[4];
    int ipcount = 0, brcount = 0, ipfullcount=0;
    int startip = 0, endip = 0;
    int j = 0, ipc= 0, brc=0;
    char *ipptr;
    char *device;
    char ip[13];
    char subnet_mask[13];
    bpf_u_int32 ip_raw; 
    bpf_u_int32 subnet_mask_raw; 
    int lookup_return_code;
    char error_buffer[PCAP_ERRBUF_SIZE]; 
    struct in_addr address, mask, broadcast, min; 
    char broadcast_address[INET_ADDRSTRLEN];
    FILE *fin;
    
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("%s\n", error_buffer);
        return 1;
    }
    
    
    lookup_return_code = pcap_lookupnet(
        device,
        &ip_raw,
        &subnet_mask_raw,
        error_buffer
    );
    if (lookup_return_code == -1) {
        printf("%s\n", error_buffer);
        return 1;
    }

   
    address.s_addr = ip_raw;
    strcpy(ip, inet_ntoa(address));
    if (ip == NULL) {
        perror("inet_ntoa"); 
        return 1;
    }
    
    
    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask, inet_ntoa(address));
    if (subnet_mask == NULL) {
        perror("inet_ntoa");
        return 1;
    }

    printf("Device: %s\n", device);
    printf("IP address: %s\n", ip);
    printf("Subnet mask: %s\n", subnet_mask);
    broadcast.s_addr = ip_raw | ~subnet_mask_raw;
    if(inet_ntop(AF_INET, &broadcast, broadcast_address, INET_ADDRSTRLEN)!=NULL)
	printf("Broadcast: %s\n",broadcast_address);
	else {
        fprintf(stderr, "Failed converting number to string\n");
    }
    printf("IP scanning ....\n");
    /*---IP address hosts calculates---*/
    for(int i=0; i<=(strlen(ip)); i++){
		if(ip[i] == '.'){
			ipcount++;
			if(ipcount == 3){
				i++;
			for(j=i; j<=(strlen(ip)); j++){
				startiparr[ipc] = ip[j];
				ipc ++;
				if(ip[j] == '\0'){
					break;
					}
				}	
			}
		}
	}
	for(int i=0; i<=(strlen(broadcast_address)); i++){
		if(broadcast_address[i] == '.'){
			brcount++;
			if(brcount == 3){
				i++;
			for(j=i; j<=(strlen(broadcast_address)); j++){
				endiparr[brc] = broadcast_address[j];
				brc ++;
				if(broadcast_address[j] == '\0'){
					break;
					}
				}	
			}
		}
	}
	startip = atoi(startiparr);
	endip = atoi(endiparr);
	for(int c=0; c<=(strlen(ip)); c++){
		ipfull[c]=ip[c];
		if(ip[c]=='.'){
		ipfullcount++;
		if(ipfullcount==3) {		
			break;
		  }
	     }
	}
	for(int j=startip+1; j<endip; j++){
		snprintf(buffstr,sizeof(buffstr),"%d",j);
		fin = fopen("ip.txt","w");
		fputs(ipfull,fin);
		fclose(fin);
		fin = fopen("ip.txt","r");
		fgets(ipbuffer,sizeof(ipbuffer),fin);
		fclose(fin);
		strcat(ipbuffer,buffstr);
		ping(ipbuffer);
		ipbuffer[0]= '\0';
	}
    return 0;
}
