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

//#define SERVER_IP "127.0.0.1"

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
连接UDP 服务器
返回 socket 文件描述符
*/
int connectToUDPServer(const char *svrip)
{
	int sockfd;
	char *hello = "Hello";

	memset(&peerAddr, 0, sizeof(peerAddr));
	peerAddr.sin_family = AF_INET;
	peerAddr.sin_port = htons(PORT_NUMBER);
	peerAddr.sin_addr.s_addr = inet_addr(svrip);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		printf("Create socket failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
	// Send a hello message to "connect" with the VPN server
	sendto(sockfd, hello, strlen(hello), 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));

	printf("Connect to server %s: %s\n", inet_ntoa(peerAddr.sin_addr), hello);
	return sockfd;
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

void combined_vpn_clinet(int argc, char *argv[])
{

int tunfd, sockfd;

	daemon(1, 1); // 守护进程

	tunfd = createTunDevice(); // 建立tun
	sockfd = connectToUDPServer(argv[1]); // 需要输入VPN服务器ip地址

	// Enter the main loop
	while (1) {
		// 监控多个接口
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
	combined_vpn_clinet(argc,argv);
}
