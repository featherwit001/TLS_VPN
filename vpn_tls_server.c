#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>

#define PORT_NUMBER 55555 // 服务器打开端口 
#define BUFF_SIZE 2000   // 缓冲区大小
#define TIMEOUT 100       // 秒
#define TUNNEL_NUM 5 

struct sockaddr_in peerAddr;
struct sockaddr_in sa_server;

/* define HOME to be dir for key and cert files... */
#define HOME	"./cert_server/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"server.crt"
#define KEYF	HOME"server.key"
#define CACERT	HOME"ca.crt"

#define PIPE   "./pipe/"



#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }


typedef struct ipheader {
    unsigned char iph_ihl:4,  // ip头长度
                  iph_ver:4;  // ip版本
    unsigned char iph_tos;    // 服务版本
    unsigned short int iph_len;  // ip包长度
    unsigned short int iph_ident;
    unsigned short int iph_flag:3,
                       iph_offset:13;
    unsigned char  iph_ttl;
    unsigned char  iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
}__attribute__((packed, aligned(4))) ipheader;


typedef struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
}__attribute__((packed, aligned(4))) tcpheader;


typedef struct tunnel_info{
	struct in_addr iph_destip; // 隧道另一端的 IP 地址
	u_short tcp_dport;         // 隧道另一端的 TCP 端口    /* destination port */
	int chilid_pid;    // 负责连接的子进程号
	char pipefilename[20];  //FIFO
} tunnel_info ;


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
	建立TCP 服务器
	返回 socket 文件描述符
*/
int setupTCPServer()
{
	
	int listen_sock;


	// 创建 TCP socket
	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	CHK_ERR(listen_sock, "socket");

	memset(&peerAddr, '\0', sizeof(peerAddr));
	peerAddr.sin_family = AF_INET;
	peerAddr.sin_addr.s_addr = INADDR_ANY;
	peerAddr.sin_port = htons(4433);
	// 服务器绑定监听端口
	int err = bind(listen_sock, (struct sockaddr *) &peerAddr, sizeof(peerAddr));

	CHK_ERR(err, "bind");

	err = listen(listen_sock, 5);// 监听连接，第二个参数表示 队列存放多少个等待的连接

	CHK_ERR(err, "listen");
	return listen_sock;
}

void processRequest(SSL * ssl, int sock)
{
	char buf[1024];
	int len = SSL_read(ssl, buf, sizeof(buf) - 1);

	buf[len] = '\0';
	printf("Received: %s\n", buf);

	// Construct and send the HTML page
	char *html = "HTTP/1.1 200 OK\r\n" "Content-Type: text/html\r\n\r\n" "<!DOCTYPE html><html>" "<head><title>Hello World</title></head>" "<style>body {background-color: black}" "h1 {font-size:3cm; text-align: center; color: white;" "text-shadow: 0 0 3mm yellow}</style></head>" "<body><h1>Hello, world!</h1></body></html>";

	SSL_write(ssl, html, strlen(html));
	SSL_shutdown(ssl);
	SSL_free(ssl);
}

SSL * setupTLSServer()
{
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	//SSL *ssl;
	int err;

	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	// Step 1: SSL context initialization
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);

	// 指明是否需要认证 SSL_VERIFY_NONE 不需要； SSL_VERIFY_PEER 需要
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	//SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	// 加载服务器 证书
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

	// Step 2: Set up the server certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}
	// Step 3: Create a new SSL structure for a connection
	return SSL_new(ctx);


}


int tun_tls_Selected(int tunfd,SSL *ssl)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from TUN\n");

	bzero(buff, BUFF_SIZE);
	
	len = read(tunfd, buff, BUFF_SIZE);
	// 判断 tun 中的数据应该发往那一个隧道
	if(len >0)
	{

		printf("\ntun packet len:%d\n",len);
		/*
		char buff_to_print[BUFF_SIZE];
		memcpy(buff_to_print,buff,len);
		buff_to_print[len] = '\0';
		printf("data from tun: \n%s\n",buff_to_print);
		*/
		tunnel_info tunnelinfo;
		ipheader * iph = (ipheader*)buff;
		memcpy(&(tunnelinfo.iph_destip), &(iph->iph_destip), sizeof(iph->iph_destip));
	
		tcpheader* tcph = (tcpheader*)(buff+sizeof(ipheader));
		memcpy(&(tunnelinfo.tcp_dport),&(tcph->tcp_dport),sizeof(iph->iph_destip));

		printf("dst ip %s, dsport %d\n",inet_ntoa(tunnelinfo.iph_destip),ntohs(tunnelinfo.tcp_dport));

	}
	else if(len == 0)
	{


		return 0;
	}
	SSL_write(ssl, buff, len);

	return 1;

	//sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));
}

/*
从socket 中 读出 数据，传入 tun
*/
int socket_tls_Selected(int tunfd, SSL *ssl)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from the tunnel\n");

	bzero(buff, BUFF_SIZE);
	
	// 从socket 读数据  需要修改
	//len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);

	len = SSL_read(ssl, buff, sizeof(buff) - 1);

	if(len >0)
	{

		printf("\nSSL packet len:%d\n",len);

	}
	else if(len ==0)
	{
		return 0;
	}
		

	write(tunfd, buff, len);

	return 1;

}



int combind_vpn_tls_server(int argc, char *argv[])
{
	int tunfd;
	tunnel_info tunnels[TUNNEL_NUM];
	int tunnel_exist =0; // 存在的隧道数量
	//daemon(1, 1);// 守护进程

	tunfd = createTunDevice();// 建立tun

	system("sudo ifconfig tun0 192.168.53.1/24 up");
	

	SSL *ssl = setupTLSServer();

	struct sockaddr_in sa_client;
	size_t client_len = sizeof(sa_client);

	int listen_sock = setupTCPServer(); // 建立连接使用socket

	fprintf(stderr, "TCP监听中..... listen_sock = %d\n", listen_sock);


	while (1) {
	// 建立连接
		int sockfd = accept(listen_sock, (struct sockaddr *) &sa_client, &client_len);// 新的socket
		if (sockfd == -1) {
			//fprintf(stderr, "Accept TCP connect failed! (%d: %s)\n", errno, strerror(errno));
			printf(" TCP 连接失败 \n");
			continue;
		}

		fprintf(stderr, "sock = %d\n", sockfd);
		// 获取对端信息
		/*
		tunnel_exist ++;
		if(tunnel_exist < TUNNEL_NUM)
		{
			struct sockaddr_in *addr = (struct sockaddr_in *)&sa_client;
			memcpy(&(tunnels[tunnel_exist].iph_destip),&(addr->sin_addr),sizeof(addr->sin_addr));
			memcpy(&(tunnels[tunnel_exist].tcp_dport),&(addr->sin_port),sizeof(addr->sin_addr));
			printf("TCP连接成功!\ndst ip %s, dsport %d\n",inet_ntoa(tunnels[tunnel_exist].iph_destip),ntohs(tunnels[tunnel_exist].tcp_dport));

		}
		else{
			printf("隧道数量受限！连接失败！\n");
			continue;
		}
		*/

		



		int pid = fork();
		
		if(pid)
		{
			close(sockfd); // 关闭建立连接的socket
			char pid_str[10] ="";
			//itoa(pid,pid_str,10);
			sprintf(pid_str,"%d",pid);
			//printf("-----------pid =%d, pid_str=%s-------------\n",pid,pid_str);

			char *pipefilename = (char *) malloc(strlen(PIPE) + strlen(pid_str)+1);
			sprintf(pipefilename , "%s%s", PIPE,pid_str);
			//printf("-----------pipe filename: %s-----------\n",pipefilename);

			tunnels[tunnel_exist].chilid_pid = pid;
			memcpy(tunnels[tunnel_exist].pipefilename,pipefilename,strlen(pipefilename)+1);

			int mkfifo_res =mkfifo(pipefilename,0666);
			if (mkfifo_res < 0) {
        		printf("create fifo failure\n");
			}
			else
			{
    			printf("create fifo success\n");
			}

			int pipefd = open(pipefilename, O_WRONLY );
			char hello[] = "hello, my child\n";
			write(pipefd,hello,strlen(hello));

		}
		else if (pid == 0) {	// The child process
			close(listen_sock);// 关闭监听的socket

			SSL_set_fd(ssl, sockfd);
			int err = SSL_accept(ssl);

			fprintf(stderr, "SSL_accept return %d\n", err);
			CHK_SSL(err);
			printf("SSL connection established!\n");
			
			// 进程信息和管道信息
			char pid_str[10] ="";
			//itoa(pid,pid_str,10);
			pid = getpid();
			sprintf(pid_str,"%d",pid);
			//printf("-----------child pid =%d, pid_str=%s-------------\n",pid,pid_str);

			char *pipefilename = (char *) malloc(strlen(PIPE) + strlen(pid_str)+1);
			sprintf(pipefilename , "%s%s", PIPE,pid_str);
			//printf("-----------child pipe filename: %s-----------\n",pipefilename);

			tunnels[tunnel_exist].chilid_pid = pid;	
			memcpy(tunnels[tunnel_exist].pipefilename,pipefilename,strlen(pipefilename)+1);
			
			// FIFO 读测试
			char buf[30];
			int pipefd = open(pipefilename, O_RDONLY);
    		int len = read(pipefd, buf, sizeof(buf));
    		write(STDOUT_FILENO, buf, len);
			
			while (1) {
				fd_set readFDSet;

				FD_ZERO(&readFDSet);
				FD_SET(sockfd, &readFDSet);
				FD_SET(tunfd, &readFDSet);

				struct timeval timeout;
				timeout.tv_sec = TIMEOUT; // 5秒超时
    			timeout.tv_usec = 0;

				int select_ret = select(FD_SETSIZE, &readFDSet, NULL, NULL, &timeout);
				printf("server select_ret: %d\n",select_ret);
				
				if(select_ret <= 0) 
				{
					//processRequest(ssl, sockfd);
					exit_server_cproc:
					SSL_shutdown(ssl);
					SSL_free(ssl);
					close(sockfd);

					int del_fifo = unlink(tunnels[tunnel_exist].pipefilename); // 关闭有名管道
					// 判断是否成功删除管道
					if (del_fifo == -1)
					{
						printf("unlink %s failed\n", tunnels[tunnel_exist].pipefilename);
						return -1;
					}
					else
					{
						printf("unlink %s success\n", tunnels[tunnel_exist].pipefilename);
					}
					printf("连接 子进程 退出 \n");
					exit(0);

				}

				if (FD_ISSET(tunfd, &readFDSet)) // tun 中有数据
				{
					// need to change
					tun_tls_Selected(tunfd, ssl); // 从tun中取出，传入socket，进入 docker1
				}

				if (FD_ISSET(sockfd, &readFDSet))// socket 中有数据
				{
					if(socket_tls_Selected(tunfd,ssl)== 0) // 表示连接中断
					{
						goto exit_server_cproc;
					}
					
					 // 从socket 中取出数据，传入tun
				}
				
			}
			

		}
	}
	
	return 0;

}

int main(int argc, char *argv[])
{
	combind_vpn_tls_server(argc, argv);
}


