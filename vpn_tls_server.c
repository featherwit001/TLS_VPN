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

#define PORT_NUMBER 55555 // 服务器打开端口 
#define BUFF_SIZE 2000   // 缓冲区大小

struct sockaddr_in peerAddr;
struct sockaddr_in sa_server;

/* define HOME to be dir for key and cert files... */
#define HOME	"./cert_server/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"server.crt"
#define KEYF	HOME"server.key"
#define CACERT	HOME"ca.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }


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


void tun_tls_Selected(int tunfd,SSL *ssl)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from TUN\n");

	bzero(buff, BUFF_SIZE);
	
	len = read(tunfd, buff, BUFF_SIZE);

	SSL_write(ssl, buff, len);

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

	if(len == 0)
		return 0;

	write(tunfd, buff, len);

	return 1;

}



int combind_vpn_tls_server(int argc, char *argv[])
{
	int tunfd;

	//daemon(1, 1);// 守护进程

	tunfd = createTunDevice();// 建立tun

	system("sudo ifconfig tun0 192.168.53.1/24 up");
	

	SSL *ssl = setupTLSServer();

	struct sockaddr_in sa_client;
	size_t client_len = sizeof(sa_client);
	int listen_sock = setupTCPServer(); // 建立连接使用socket

	fprintf(stderr, "listen_sock = %d\n", listen_sock);


	while (1) {
	// 建立连接
		int sockfd = accept(listen_sock, (struct sockaddr *) &sa_client, &client_len);// 新的socket
		fprintf(stderr, "sock = %d\n", sockfd);
		if (sockfd == -1) {
			//fprintf(stderr, "Accept TCP connect failed! (%d: %s)\n", errno, strerror(errno));
			printf(" TCP 连接失败 \n");
			continue;
		}

		if (fork() == 0) {	// The child process
			close(listen_sock);// 关闭监听的socket

			SSL_set_fd(ssl, sockfd);
			int err = SSL_accept(ssl);

			fprintf(stderr, "SSL_accept return %d\n", err);
			CHK_SSL(err);
			printf("SSL connection established!\n");
			

			while (1) {
				fd_set readFDSet;

				FD_ZERO(&readFDSet);
				FD_SET(sockfd, &readFDSet);
				FD_SET(tunfd, &readFDSet);

				struct timeval timeout;
				timeout.tv_sec = 5; // 5秒超时
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
					printf("连接 子进程 退出 \n");
					exit(0);

				}

				if (FD_ISSET(tunfd, &readFDSet)) // tun 中有数据
				{
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
			

		} else {	// The parent process
			close(sockfd); // 关闭建立连接的socket
		}

	}


}

int main(int argc, char *argv[])
{
	combind_vpn_tls_server(argc, argv);
}


