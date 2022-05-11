#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#define PORT_NUMBER 55555 // 服务器打开端口 
#define BUFF_SIZE 2000   // 缓冲区大小

struct sockaddr_in peerAddr;

//建立TUN 设备
//返回 文件描述符
int createTunDevice()
{
	int tunfd;
	struct ifreq ifr;
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd == -1) {
		printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
	ret = ioctl(tunfd, TUNSETIFF, &ifr);
	if (ret == -1) {
		printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	printf("Setup TUN interface success!\n");
	return tunfd;
}

/*
	初始化UDP 服务器
	返回socket 文件描述符
*/
int initUDPServer()
{
	int sockfd;
	struct sockaddr_in server;
	char buff[100];

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(PORT_NUMBER);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		printf("Create socket failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	bind(sockfd, (struct sockaddr *) &server, sizeof(server));

	// Wait for the VPN client to "connect".
	bzero(buff, 100);
	int peerAddrLen = sizeof(struct sockaddr_in);
	int len = recvfrom(sockfd, buff, 100, 0,
			   (struct sockaddr *) &peerAddr, &peerAddrLen);

	printf("Accept connect from client %s: %s\n", inet_ntoa(peerAddr.sin_addr), buff);
	return sockfd;
}

/*
	建立TCP 服务器
	返回socket 文件描述符
*/
int setupTCPServer()
{
	struct sockaddr_in sa_server;
	int listen_sock;

	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	CHK_ERR(listen_sock, "socket");
	memset(&sa_server, '\0', sizeof(sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr.s_addr = INADDR_ANY;
	sa_server.sin_port = htons(4433);
	int err = bind(listen_sock, (struct sockaddr *) &sa_server, sizeof(sa_server));

	CHK_ERR(err, "bind");
	err = listen(listen_sock, 5);
	CHK_ERR(err, "listen");
	return listen_sock;
}


/*
从tun 中 读出 数据，传入 socket
*/
void tunSelected(int tunfd, int sockfd)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from TUN\n");

	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE);
	sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));
}

/*
从socket 中 读出 数据，传入 tun
*/
void socketSelected(int tunfd, int sockfd)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from the tunnel\n");

	bzero(buff, BUFF_SIZE);
	len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
	write(tunfd, buff, len);

}

void combined_vpn_server(int argc, char *argv[])
{
	int tunfd, sockfd;

	daemon(1, 1);// 守护进程

	tunfd = createTunDevice();// 建立tun
	sockfd = initUDPServer(); // 初始化监听端口

	// Enter the main loop
	while (1) {
		fd_set readFDSet;

		FD_ZERO(&readFDSet);
		FD_SET(sockfd, &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

		if (FD_ISSET(tunfd, &readFDSet)) // tun 中有数据
		{
			tunSelected(tunfd, sockfd); // 从tun中取出，传入socket，进入 docker1
		}

		if (FD_ISSET(sockfd, &readFDSet))// socket 中有数据
		{
			socketSelected(tunfd, sockfd); // 从socket 中取出数据，传入tun
		}
	}
}



int main(int argc, char *argv[])
{
	combined_vpn_server(argc,argv);
}
