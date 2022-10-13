#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdbool.h>
#include <fcntl.h>
#include "stun.h"

void start(char **argv)
{
	struct sockaddr_in servaddr, remoteaddr, localaddr;
	int n;
	int sockfd;
	char return_ip[32]; 
	unsigned short return_port=0;
	char* stun_server_name = argv[1];
	uint16_t stun_server_port = atoi(argv[2]);
	uint16_t stun_client_port = atoi(argv[3]);
	
    // create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0); 
	if(sockfd == -1) handle_error("socket()\n");

	// server & DNS 
	memset(&servaddr, 0, sizeof(struct sockaddr_in));	
	struct addrinfo* stunAddr = NULL;
    getaddrinfo(stun_server_name, NULL, NULL, &stunAddr);
    if (stunAddr != NULL) {
        struct addrinfo* root = stunAddr;
        while (stunAddr->ai_next != NULL)
        {
            if (stunAddr->ai_family == AF_INET) {
				memcpy(&servaddr, stunAddr->ai_addr, stunAddr->ai_addrlen);
                freeaddrinfo(root);
                break;
            }
            stunAddr = stunAddr->ai_next;
        }
    }
	servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(stun_server_port);	

	// server
    // memset(&servaddr, 0, sizeof(struct sockaddr_in));
    // servaddr.sin_family = AF_INET;
    // servaddr.sin_port = htons(stun_server_port);	
	// inet_pton(AF_INET, stun_server_ip, &servaddr.sin_addr.s_addr);

    // host address
    memset(&localaddr, 0, sizeof(struct sockaddr_in));
    localaddr.sin_family = AF_INET;
    localaddr.sin_port = htons(stun_client_port);

	/* Biding local address to socket */
	bind(sockfd, (struct sockaddr *)&localaddr, sizeof(struct sockaddr));

	n = stun_implement(sockfd, servaddr, return_ip, &return_port);
	if (n!=0) 
		handle_error("stun_implement()\n");
	else {
		char local_ip_addr[LOCAL_ADDR_LEN];
		printf("\nlocal address <ip> <port> : %s %d\n", get_localaddr(local_ip_addr, LOCAL_ADDR_LEN), stun_client_port);
		printf("public address <ip> <port> : %s %d\n", return_ip, return_port);
	}

	//communicate(sockfd);	
	symmetric_natt(remoteaddr);
	close(sockfd);
}

int stun_implement(int sockfd, struct sockaddr_in servaddr, char* return_ip, unsigned short* return_port)
{
	unsigned char buf[MAX_SIZE_BUF];
    unsigned char stun_request[STUN_HDR_LEN];    

	int stun_method, msg_length;
	short attr_type;
	short attr_length;
	short port;
	short n;


    // first bind 
	* (short *)(&stun_request[0]) = htons(STUN_BINDING_METHOD);    // stun_method rfc 5389
	* (short *)(&stun_request[2]) = htons(0x0000);    //msg_length: do not contain payload
	* (int *)(&stun_request[4])   = htonl(MAGIC_COOKIE);

	*(int *)(&stun_request[8]) = htonl(0x63c7117e);   // transacation ID 
	*(int *)(&stun_request[12])= htonl(0x0714278f);
	*(int *)(&stun_request[16])= htonl(0x5ded3221);

    n = sendto(sockfd, stun_request, sizeof(stun_request), 0, (const struct sockaddr *) &servaddr, sizeof(servaddr)); 
	if (n == -1) 
		handle_error("sendto()\n");
	usleep(1000 * 100);

	memset(buf, 0, sizeof(buf));
    n = recvfrom(sockfd, buf, 300, 0, NULL, 0);
    if (n == -1) 
		handle_error("recvfrom()\n");

	if (*(short *)(&buf[0]) == htons(STUN_RESPONE_SUCCESS));
	{

		n = htons(*(short *)(&buf[2]));	//n = Message Length = 48 
		int i = STUN_HDR_LEN;
			/*Tìm kiếm XOR MAPPED ATTRIBUTE trong Respone msg*/
        	while(i<sizeof(buf))	
       	 	{
				attr_type = htons(*(short *)(&buf[i]));
				attr_length = htons(*(short *)(&buf[i+2]));
				if (attr_type == XOR_MAPPED_ADDR_ATTR)
				{
					port = ntohs(*(short *)(&buf[i+6]));
					port ^= 0x2112;

						/*Get public endpoint of STUN client*/ 
					*return_port = port;
					sprintf(return_ip,"%d.%d.%d.%d",buf[i+8]^0x21,buf[i+9]^0x12,buf[i+10]^0xA4,buf[i+11]^0x42);
					break;
				}
				/* Sau mỗi vòng loop sẽ duyệt qua một attribute trong STUN respone
				Biến i trỏ sang attribute kế tiếp với i = i + 4 + attr_length
				Trong đó:	4 - STUN Attribute header length
							attr_length - STUN Attribute Value length			*/
				i += (STUN_ATTR_HDR_LEN + attr_length);	
        	}
	}

	return 0;
}

char* get_localaddr(char *info, int n)
{
	struct ifaddrs *addresses;
	struct in_addr *tmpAddrPtr;
	if (getifaddrs(&addresses) == -1) 
		handle_error("getifaddrs()\n");

	struct ifaddrs *address = addresses;
	while(address) 
	{
		int family = address->ifa_addr->sa_family;
		if (family == AF_INET) {
			tmpAddrPtr=&((struct sockaddr_in *)address->ifa_addr)->sin_addr;
			/*Covert uint32_t IP address at tmpAddrPtr to char pointed by info*/
			inet_ntop(AF_INET, tmpAddrPtr, info, n);
			if (strcmp(info, "127.0.0.1") != 0) 
				break;
				memset(info, 0, n);
		}
		address = address->ifa_next;
	}
	freeifaddrs(addresses);
	return info;
}

void communicate(int sockfd)
{
	char buf[100] = "/0";
	struct sockaddr_in remote_addr;
	char remote_ip[30];
	int remote_port;

	printf("\nConnecting to... <remote_ip> <remote_port> : ");
	scanf("%s %d", remote_ip, &remote_port);
	printf("\nWaiting for connection...\n");

	//remote 
    memset(&remote_addr, 0, sizeof(struct sockaddr_in));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(remote_port);	
	inet_pton(AF_INET, remote_ip, &remote_addr.sin_addr.s_addr);

	/*UDP Hole Punching*/
	int n;
	int sendCheck = 0;
	static int count = 10;
	char temp[30] = "HolePunching\n";

	/*Set socket to non-blocking socket*/
	int opts;
	opts = fcntl(sockfd,F_GETFL);
    if (opts < 0) {
        perror("fcntl(F_GETFL)");
        exit(EXIT_FAILURE);
    }
	int new_opts = opts;
    new_opts = (new_opts | O_NONBLOCK);
    if (fcntl(sockfd,F_SETFL,new_opts) < 0) {
        perror("fcntl(F_SETFL)");
        exit(EXIT_FAILURE);
    }

	while (1)
	{	
		memcpy(buf, temp, sizeof(temp));
		sendCheck = sendto(sockfd, buf, sizeof(buf), 0, (const struct sockaddr *) &remote_addr, sizeof(remote_addr));
		if (sendCheck > 0) {
			count--;
			printf("\nTry to send %d UDP packet to remote addr.\n", 10 - count);
		}
		memset(buf, 0, sizeof(buf));
		n = recvfrom(sockfd, buf, 300, 0, NULL, 0);
		if (n > 0) {
			memset(buf, 0, sizeof(buf));
			printf("\nRecv the first UDP packet from remote addr successfully.\n");
			break;
		}
		sleep(1);
	}

	sleep(1);

	//Clear socket buffer
	while(read(sockfd, buf, sizeof(buf)) > 0) {
            strcpy(buf, ""); //attempt to erase all old values
            fflush(stdout);
        }

	/*Set socket to blocking mode**
    * if (fcntl(sockfd,F_SETFL,opts) < 0) {
    *    perror("fcntl(F_SETFL)");
    *    exit(EXIT_FAILURE);
    * }
	* printf("\nUDP Hole Punching Successful.\nStart to communicate..\n");
	* */

	while (1)
	{
		fflush(stdin);
		fgets(buf, 100, stdin);
		sendto(sockfd, buf, sizeof(buf), 0, (const struct sockaddr *) &remote_addr, sizeof(remote_addr)); 
		memset(buf, 0, sizeof(buf));

		recvfrom(sockfd, buf, 300, 0, NULL, 0);
		printf("%s", buf);
		memset(buf, 0, sizeof(buf));
	}
	
}

static int send_dummy_udp_packet(int fd, struct sockaddr_in remoteaddr) {
    char dummy = 'c';

    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    
    return sendto(fd, &dummy, 1, 0, (struct sockaddr *)&remoteaddr, sizeof(remoteaddr));
}

static int punch_hole(struct sockaddr_in peer_addr) {
    int symsock = socket(AF_INET, SOCK_DGRAM, 0);
    if (symsock != -1) {
        if (send_dummy_udp_packet(symsock, peer_addr) < 0) {
            return -1;
        }
    }
    return symsock;
}

static int wait_for_peer(int* socks, int sock_num, struct timeval *timeout) {
    fd_set fds;  
    int max_fd = 0;
    FD_ZERO(&fds);

    int i;
    for (i = 0; i < sock_num; ++i) {
        FD_SET(socks[i], &fds);
        if (socks[i] > max_fd) {
            max_fd = socks[i];
        }
    }
    int ret = select(max_fd + 1, &fds, NULL, NULL, timeout);

    int index = -1;
    if (ret > 0) {
        for (i = 0; i < sock_num; ++i) {
            if (FD_ISSET(socks[i], &fds)) {
                index = i;
                break;
            }
        }
    } else {
        // timeout or error
    }

    // one of the fds is ready, close others
    if (index != -1) {
        for (i = 0; i < sock_num; ++i) {
            if (index != i) {
                close(socks[i]);
            }
        }

        return socks[index];
    }

    return -1;
}

void on_connected(int sock) {
    char buf[MSG_BUF_SIZE] = {0};
    struct sockaddr_in remote_addr;
    socklen_t fromlen = sizeof remote_addr;
    recvfrom(sock, buf, MSG_BUF_SIZE, 0, (struct sockaddr *)&remote_addr, &fromlen);
    printf("recv %s\n", buf);

    printf("connected with peer from %s:%d\n", inet_ntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port));
    sendto(sock, "hello, peer", strlen("hello, peer"), 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
}



int symmetric_natt()
{
	struct sockaddr_in remoteaddr;
	char remoteip[30];
	int remoteport;
	printf("\nConnecting to... <remote_ip> <remote_port> : ");
	scanf("%s %d", remoteip, &remoteport);
	printf("\nWaiting for connection...\n");

	//remote 
    memset(&remoteaddr, 0, sizeof(struct sockaddr_in));
    remoteaddr.sin_family = AF_INET;
    remoteaddr.sin_port = htons(remoteport);	
	inet_pton(AF_INET, remoteip, &remoteaddr.sin_addr.s_addr);

	int ports[NUM_OF_PORTS] = {0};
	int symsock[NUM_OF_PORTS];
	for (int i = 0; i < NUM_OF_PORTS; i++)
	{
		srand(time(NULL));
		ports[i] = (rand() % (MAX_PORT - MIN_PORT + 1)) + MIN_PORT;
		if (ports[i] != remoteaddr.sin_port) {
			remoteaddr.sin_port = htons(ports[i]);
			if (symsock[i] = punch_hole(remoteaddr) < 0) {
				printf("\nNAT in front of us wound't tolerate too many ports used by one application\n");
				break;
			}
			usleep(1000*100);
		} else {
			ports[i] = ports[1000];
			continue;
		}
	}
	struct timeval timeout={100, 0};
		int fd = wait_for_peer(symsock, NUM_OF_PORTS - 1, &timeout);
		if (fd > 0) {
			on_connected(fd);
		} else {
			int j = 0;
			for (; j < NUM_OF_PORTS - 1; ++j) {
				close(symsock[j]);
			}
			printf("timout, not connected\n");
		}

	return 0;
}	

