#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#define PORT_NUMBER 55555 // 服务器打开端口 
#define BUFF_SIZE 2000   // 缓冲区大小

struct sockaddr_in peerAddr;
struct sockaddr_in server_addr;

/* define HOME to be dir for key and cert files... */
#define HOME	"./cert_server/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"client.crt"
#define KEYF	HOME"client.key"
#define CACERT	HOME"ca.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_SSL(err)	if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }


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

int verify_callback(int preverify_ok, X509_STORE_CTX * x509_ctx)
{
	char buf[300];

	X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
	printf("subject= %s\n", buf);

	if (preverify_ok == 1) {
		printf("Verification passed.\n");
	} else {
		int err = X509_STORE_CTX_get_error(x509_ctx);

		printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
	}
}

SSL *setupTLSClient(const char *hostname)
{
	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;

	// 创建 SSL 上下文
	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);
	// 指明是否需要认证 SSL_VERIFY_NONE 不需要； SSL_VERIFY_PEER 需要
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);


	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-2);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-3);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Private key does not match the certificate public keyn");
		exit(-4);
	}

	// 创建新的 SSL 结构 用于连接
	ssl = SSL_new(ctx);

	//启用主机名检查
	X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
	X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

	return ssl;
}

/*
	建立TCP 客户端
	返回 socket 文件描述符
*/
int setupTCPClient(const char *hostname, int port) // 输入客户端地址和端口
{
	
	// Get the IP address from hostname
	struct hostent *hp = gethostbyname(hostname);

	// Create a TCP socket
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// Fill in the destination information (IP, port #, and family)
	memset(& peerAddr, '\0', sizeof( peerAddr));
	memcpy(&( peerAddr.sin_addr.s_addr), hp->h_addr, hp->h_length);
	// peerAddr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
	 peerAddr.sin_port = htons(port);
	 peerAddr.sin_family = AF_INET;
 
	// Connect to the destination
	connect(sockfd, (struct sockaddr *) & peerAddr, sizeof(peerAddr));

	return sockfd;
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
	
	// 从socket 读数据
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

void combind_tls_client(int argc, char *argv[])
{
	char *hostname = "yahoo.com";
	int port = 443;

	if (argc > 1)
		hostname = argv[1];
	if (argc > 2)
		port = atoi(argv[2]);

	/*----------------TLS initialization ----------------*/
	SSL *ssl = setupTLSClient(hostname);

	/*----------------Create a TCP connection ---------------*/
	int sockfd = setupTCPClient(hostname, port);

	/*----------------TLS handshake ---------------------*/
	SSL_set_fd(ssl, sockfd);
	CHK_NULL(ssl);
	int err = SSL_connect(ssl);

	CHK_SSL(err);
	printf("SSL connection is successful\n");
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/*----------------Send/Receive data --------------------*/
	char buf[9000];
	char sendBuf[200];

	sprintf(sendBuf, "GET / HTTP/1.1\nHost: %s\n\n", hostname);
	SSL_write(ssl, sendBuf, strlen(sendBuf));

	int len;

	do {
		len = SSL_read(ssl, buf, sizeof(buf) - 1);
		buf[len] = '\0';
		printf("%s\n", buf);
	} while (len > 0);

}

/*
从tun 中 读出 数据，传入 socket
*/
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
void socket_tls_Selected(int tunfd, SSL *ssl)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from the tunnel\n");

	bzero(buff, BUFF_SIZE);
	
	// 从socket 读数据  需要修改
	//len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);

	len = SSL_read(ssl, buff, sizeof(buff) - 1);

	write(tunfd, buff, len);

}




void combind_vpn_tls_client(int argc, char *argv[])
{
	int tunfd, sockfd;

	daemon(1, 1); // 守护进程

	char *hostname = "yahoo.com";
	int port = 443;

	if (argc > 1)
		hostname = argv[1];
	if (argc > 2)
		port = atoi(argv[2]);


	tunfd = createTunDevice(); // 建立tun

		/*----------------TLS initialization ----------------*/
	SSL *ssl = setupTLSClient(hostname);

	/*----------------Create a TCP connection ---------------*/
	int sockfd = setupTCPClient(hostname, port);

	/*----------------TLS handshake ---------------------*/
	SSL_set_fd(ssl, sockfd);
	CHK_NULL(ssl);
	int err = SSL_connect(ssl);

		CHK_SSL(err);
	printf("SSL 连接成功\n");
	printf("SSL 连接使用 %s\n", SSL_get_cipher(ssl));


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
			//tunSelected(tunfd, sockfd); // 从tun中取出，传入socket，进入 docker1
			tun_tls_Selected(tunfd,ssl);

		}

		if (FD_ISSET(sockfd, &readFDSet))// socket 中有数据
		{
			//socketSelected(tunfd, sockfd); // 从socket 中取出数据，传入tun
		
			socket_tls_Selected(tunfd,ssl);
		
		}
			
	}


}


int main(int argc, char *argv[])
{
	
}
