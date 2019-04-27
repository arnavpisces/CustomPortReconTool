//Arnav Kumar - 2016017
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>   
#include <netinet/ip.h>    
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#define LIMIT 20000
struct args
{
 int sockNum;
 char datagram[4096];
};

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};
 
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}
 
void *sendRaw(void *arguments){

    int i=0;
    for(i=0;i<LIMIT;i++){
        struct args *arg = arguments;
        // printf("Sock number %d\n",arg->sockNum);
        int sockNum=arg->sockNum;
        char datagram[4096] , source_ip[32] , dest_ip[32], *data , *pseudogram;
        strcpy(source_ip , "192.168.216.167");
        strcpy(dest_ip , "192.168.216.148");
        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = htons(8989);
        sin.sin_addr.s_addr = inet_addr ("192.168.216.148");
        
        struct iphdr *iph = (struct iphdr *) datagram;
        struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
        
        //For TCP checksum calculation
        struct pseudo_header psh;
        
        //The payload of the datagram
        data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
        strcpy(data , "");

        //IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
        iph->id = htonl (54321); 
        iph->frag_off = 0;
        iph->ttl = 255;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;      
        iph->saddr = inet_addr ( source_ip );    
        iph->daddr = inet_addr( dest_ip );
        
        //CheckSum Calculation
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);
        
        //TCP Header
        tcph->source = htons (8989); //Source Port
        tcph->dest = htons (i); //Destination Port
        tcph->seq = 0;
        tcph->ack_seq = 27;
        tcph->doff = 5;  //tcp header size
        tcph->fin=0;
        tcph->syn=1;
        tcph->rst=0;
        tcph->psh=0;
        tcph->ack=0;
        tcph->urg=0;
        tcph->window = htons (5840); /* maximum allowed window size */
        tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
        tcph->urg_ptr = 0;
        
        //Now the TCP checksum
        psh.source_address = inet_addr( source_ip );
        psh.dest_address = inet_addr( dest_ip );
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );
        
        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
        pseudogram = malloc(psize);
        
        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));
        
        tcph->check = csum( (unsigned short*) pseudogram , psize);
        
        //IP_HDRINCL to tell the kernel that headers are included in the packet
        int one = 1;
        const int *val = &one;

        if (setsockopt (sockNum, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        {
            perror("Error setting IP_HDRINCL");
            exit(0);
        }
        while (1)
        {
            if (sendto (sockNum, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
            {
                perror("sendto failed");
            }
            else
            {
                // printf ("Packet Send. Length : %d \n" , iph->tot_len);
            }
            break;
        }
    }

    pthread_exit(NULL);

}

void *recvRaw(int sockNum){
    int ports[100];
    int j=0;
    for(j=0;j<100;j++){
        ports[j]=0;
    }
    j=0;
    int lastPortRec=0;
    
    int listen=0;
    while(1){
        int buflen;
        char buffer[65536]={0};
        struct sockaddr saddr;
        int saddr_len = sizeof (saddr);

        buflen=recvfrom(sockNum,buffer,65536,0,&saddr,(socklen_t *)&saddr_len);
        if(buflen==40){
            listen++;
        }
        // printf("%d\n",listen);
        if(listen==9000){
            // break; //Jugaad counter, don't require this anymore.
        }
        // printf("buflen %d\n",buflen);
        // printf("packet received\n");
        if(buflen<0)
        {
        printf("error in reading recvfrom function\n");
        return -1;
        }
        struct iphdr *iph = (struct iphdr *) buffer;
        struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof (struct ip));
        if(tcph->syn && tcph->ack){
            printf("TCP response from port: %d\n",ntohs(tcph->source));
            ports[j]=ntohs(tcph->source);
            j++;
        }
        else if(tcph->rst && tcph->ack){
            lastPortRec=ntohs(tcph->source);
            if(lastPortRec==LIMIT-1){
                break;
            }
        }
        fflush(stdout);
        // printf("the packet saddr is %x\n",iph->saddr);
    }
    printf("Scan done on ip address 192.168.216.148\n");
    printf("PORT\t\tSTATE\n");
    for(j=0;ports[j]!=0;j++){
        printf("%d\t\topen\n",ports[j]);
    }
    pthread_exit(NULL);
}

int main (void)
{
    //Create a raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
     
    if(s == -1)
    {
        perror("Failed to create socket");
        exit(1);
    }
     
    struct args argForThread;
    argForThread.sockNum=s; 

    pthread_t sender;
    pthread_t receiver;

    if(pthread_create(&sender,NULL,&sendRaw,(void *)&argForThread)!=0){
        perror("Sender Thread Error: ");
    }
    if(pthread_create(&receiver,NULL,&recvRaw,s)!=0){
        perror("Sender Thread Error: ");
    }
    pthread_join(sender,NULL);
    pthread_join(receiver,NULL);
         
    return 0;
}
 