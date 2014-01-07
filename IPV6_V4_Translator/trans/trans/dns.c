#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdlib.h>
#include <pthread.h>
#include <bits/pthreadtypes.h>


unsigned char* ReadName (unsigned char*,unsigned char*,int*);
void *chld(void *mysock);
int send_to_DNS(char *buff, struct sockaddr_in6 clnt_addr);
unsigned char* change_type(unsigned char *);

/* ------ DNS Header Structure ------ */
struct DNS_HEADER
{
	unsigned short id;       // identification number
	unsigned char rd :1;     // recursion desired
	unsigned char tc :1;     // truncated message
	unsigned char aa :1;     // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1;     // query/response flag
	unsigned char rcode :4;  // response code
	unsigned char cd :1;     // checking disabled
	unsigned char ad :1;     // authenticated data
	unsigned char z :1;      // its z! reserved
	unsigned char ra :1;     // recursion available
	unsigned short q_count;  // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
	};

/* DNS Question Structure 
QNAME is variable. Not Included
*/

struct QUESTIONS
{
	unsigned short qtype;
	unsigned short qclass;
	};

/* ------ DNS Resource Data Structure ------ 
Name field is variable. Not Included
*/

struct R_DATA

{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
	};

struct RES_RECORD
{
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};
	 
typedef struct 
{
	unsigned char *name;
	struct QUESTION *ques;
} QUERY;

struct thread_data{
   char *buf;
   struct sockaddr_in6 addr;
};

struct thread_data thread_data_array[1000];


struct sockaddr_in6 server_addr;
int sock_client, addr_len;
int adr_len = sizeof(struct sockaddr *);
int main()
{
	struct DNS_HEADER *dns_client;  			// DNS packet recieve from client
	struct DNS_HEADER *dns_server;  			// DNS reply from Server
	unsigned char buf_client[1000];
        //int addr_len, bytes_read;
        struct sockaddr_in6 client_addr;

        
/*
Socket for Accepting Request on Port 53
*/
	

	struct in6_addr to_addr;
        int server_sock,bytes_sent;
        if ((sock_client = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
                printf("error");
        }
        if(inet_pton(AF_INET6,"4001:4490::c0a8:103",&to_addr)<=0){
        }
        server_addr.sin6_family=AF_INET6;
        server_addr.sin6_port=htons(53);
        //server.sin6_addr = in6addr_loopback;
        server_addr.sin6_addr=to_addr;
        server_addr.sin6_scope_id=1;
        bytes_sent=bind(sock_client, (struct sockaddr *)&server_addr, sizeof(server_addr));


	
	int count=0;
	struct sockaddr_in6 test;

	addr_len = sizeof(struct sockaddr*);

// Loop for accepting requests
	while(1){
		 int client_sockfd = recvfrom (sock_client,(char*)buf_client,1000,0,(struct sockaddr *)&client_addr, &addr_len);
		int accept=check(&buf_client);

		if(accept == 1)
		{
			thread_data_array[count].buf = buf_client;
			thread_data_array[count].addr = client_addr;
			pthread_t thread;
			int res=pthread_create(&thread, NULL, &chld, &thread_data_array[count]);
		}

		count++;
		fflush(stdout);
	}
	return 0;
}


/*
Check Qtype = 28 or Other
*/

int check(char* buffer)
{
	int of = 0;
	int loc;
	int rt=0;
	of = of + 13;
	loc = readname(buffer, of);	
	if(buffer[loc+1] == 28)
	{
		rt=1;
	}
	else
	{
		rt=0;
	}
	return rt;
}
	
int readname(unsigned char* buf, int off)
{
	if(buf[off]>=192)
	{
		off=off+2;
	}
	else
	{
		while(buf[off]!=0)
		{
			off=off++;
		}
	off=off+1;
	}
	return off;
}

void *chld(void *threadarg){

	struct thread_data *data;
	struct sockaddr_in6 clnt_addr;
	data = (struct thread_data *) threadarg;
	char *buff = data->buf;
	clnt_addr = data->addr;
	int of=0;
	int loc;
	of = of + 13;
	loc = readname(buff, of);
	buff[loc+1] = 1;
	int x=send_to_DNS(buff, clnt_addr);
	fflush(stdout);
	pthread_exit(NULL);
}

int send_to_DNS(char *buff, struct sockaddr_in6 clnt_addr){
	unsigned char buf_server[1000];
	int sock_server;
	struct DNS_HEADER *dns1;

	
	
	struct sockaddr_in6 dest;
 	struct in6_addr to_addr;
        int server_sock,bytes_sent;
        if ((sock_server = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
                printf("error");
        }
        if(inet_pton(AF_INET6,"2001:df0:92:0:21e:8cff:fec7:437f",&to_addr)<=0){
        }
        dest.sin6_family=AF_INET6;
        dest.sin6_port=htons(53);
        //server.sin6_addr = in6addr_loopback;
        dest.sin6_addr=to_addr;
        dest.sin6_scope_id=1;
	
	int test = sendto(sock_server,(char*)buff,1000 ,0,(struct sockaddr*)&dest, addr_len);
	recvfrom (sock_server,(char*)buf_server,1000,0,(struct sockaddr*)&dest, &adr_len);
	dns1=(struct DNS_HEADER*) buf_server;

	int of = 13;
        int loc,k;
        loc = readname(buf_server, of);
        buf_server[loc + 1] = 28;
	loc = loc + 4;
	of = loc;
	int i;
        for(i=0;i<ntohs(dns1->ans_count);i++)
        {
		loc = readname(buf_server, loc);
	        if (buf_server[loc + 1] == 1)
		{
			buf_server[loc + 1] = 28;
	        	buf_server[loc + 9] = 16;
		        for(k=500;k>=10;k--)
        		{
		                buf_server[loc+k+12]=buf_server[loc+k];

        		}
	        buf_server[loc+10]=0x40;
        	  buf_server[loc+11]=0x01;
	        buf_server[loc+12]=0x44;
	        buf_server[loc+13]=0x90;
	        buf_server[loc+14]=0x00;
	        buf_server[loc+15]=0x00;
	        buf_server[loc+16]=0x00;
	        buf_server[loc+17]=0x00;
	        buf_server[loc+18]=0x00;
	        buf_server[loc+19]=0x00;
	        buf_server[loc+20]=0x00;
	        buf_server[loc+21]=0x00;

		}
		
		loc = loc + 9 + buf_server[loc + 9] + 1;
		
	}
	int l=0;
	sendto(sock_client,(char*)buf_server,500 ,0,(struct sockaddr*)&clnt_addr, addr_len);
}	

