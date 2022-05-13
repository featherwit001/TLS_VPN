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

#include<pthread.h>

#include <shadow.h>
#include <crypt.h>

#define PORT_NUMBER 55555 // 服务器打开端口 
#define BUFF_SIZE 2000   // 缓冲区大小
#define TIMEOUT 100       // 秒
#define TUNNEL_NUM 5 

struct sockaddr_in peerAddr;
struct sockaddr_in sa_server;
int tunfd;// tun 文件描述符
//int pipeTgetP; // 子线程获得子进程信息
/* define HOME to be dir for key and cert files... */
#define HOME	"./cert_server/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"server.crt"
#define KEYF	HOME"server.key"
#define CACERT	HOME"ca.crt"

#define GlobalPIPE "./pipe/P2T" // childproc to pipe 
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

//单个隧道的信息
typedef struct tunnel_info{
	struct in_addr iph_destip; // 隧道另一端的 IP 地址
	u_short tcp_dport;         // 隧道另一端的 TCP 端口    /* destination port */
	int chilid_pid;    // 负责连接的子进程号
	char pipefilename[20];  //FIFO
	int pipefd;
	int info_seted;
} tunnel_info ;

//全体隧道信息整合
typedef struct tunnels{
	int tunnel_num;
	int info_all_seted;
	tunnel_info tunnel_infos[TUNNEL_NUM];
}tunnels;

static pthread_mutex_t g_mutex_lock;
//static pthread_rwlock_t myrwlock;

typedef struct infoP2T{
	struct in_addr iph_destip; // 隧道另一端的 IP 地址
	u_short tcp_dport;         // 隧道另一端的 TCP 端口
	int chilid_pid;    // 负责连接的子进程号
	int func;     // 功能标志 创建 1 销毁 2
}infoP2T;




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

/*
int tun_tls_Selected(int tunfd,SSL *ssl)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from TUN\n");

	bzero(buff, BUFF_SIZE);
	
	len = read(tunfd, buff, BUFF_SIZE);
	if(len >0)
	{

		printf("\ntun packet len:%d\n",len);
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
}*/

//子进程从pipe 中读取数据，写入ssl
int pipe_tls_Selected(int pipefd,SSL *ssl)
{

	int len;
	char buff[BUFF_SIZE];
	
	printf("\nchild proc %d Got a packet from pipe\n",getpid());

	bzero(buff, BUFF_SIZE);
	
	len = read(pipefd, buff, BUFF_SIZE);

	if(len >0)
	{
		// 展示信息
		printf("pipe packet len:%d\n",len);

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
}

/*
从socket 中 读出 数据，传入 tun
*/
int socket_tls_Selected(SSL *ssl,int tunfd)
{
	int len;
	char buff[BUFF_SIZE];
	static int isFirst = 0;


	//printf("Got a packet from the tunnel\n");

	bzero(buff, BUFF_SIZE);
	
	// 从socket 读数据  需要修改
	//len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);

	len = SSL_read(ssl, buff, sizeof(buff) - 1);

	if(len >0)
	{

		//printf("\nSSL packet len:%d\n",len);
			infoP2T tunnelinfo;
			tunnelinfo.chilid_pid = getpid();
			printf("\n---------------------SSL pid: %d  转发信息---------------------------\n",tunnelinfo.chilid_pid);
			printf("SSL packet len:%d\n",len);
			
			ipheader * iph = (ipheader*)buff;
			memcpy(&(tunnelinfo.iph_destip), &(iph->iph_sourceip), sizeof(iph->iph_sourceip));// 源地址为 返回包的目的地址
			tcpheader* tcph = (tcpheader*)(buff+sizeof(ipheader));
			memcpy(&(tunnelinfo.tcp_dport),&(tcph->tcp_sport),sizeof(tcph->tcp_sport)); 	

			printf("------------SSL  dst ip %s, dsport %d\n",inet_ntoa(tunnelinfo.iph_destip),ntohs(tunnelinfo.tcp_dport));
			//展示信息
			
		if(isFirst == 0) // 第一次进入
		{	
			if(tunnelinfo.iph_destip.s_addr != 0)
			{	
				printf("---------------------SSL反馈 pid: %d 返回路径---------------------------\n",tunnelinfo.chilid_pid);
				tunnelinfo.func =1 ; // 创建隧道
				int pipeP2T = open( GlobalPIPE, O_WRONLY );
				write(pipeP2T,&tunnelinfo,sizeof(tunnelinfo)); // 传给隧道信息管理线程
				close(pipeP2T); // 关闭写入口
				isFirst = 1;	
				sleep(1);  // 睡眠一秒，等待packet distributor 配置成功
			}			
		}

	}
	else if(len ==0)
	{
		return 0;
	}
		

	write(tunfd, buff, len);

	return 1;

}

// tun 数据分配线程，通过FIFO 传递给 子进程
//// 由数据包分配进程控制
// 从tun 中读取数据，传入pipe
void* setup_tun_data_distributor(void *TUNNELS)
{
	tunnels * t =(tunnels *) TUNNELS;
	while(1)
	{
		pthread_mutex_lock(&g_mutex_lock);
		if( t->tunnel_num == 0 ||  t->info_all_seted == 0)
		{
			
			//隧道数量为0 或者 隧道信息未设置完毕
			printf("tun 数据分配器 休眠中... ");
			printf("现有隧道 %d 条\n", t->tunnel_num);

 			pthread_mutex_unlock(&g_mutex_lock);

			sleep(1); //休眠等待
			
			continue;
		}
		else{
			printf("tun 数据分配器 运行中... ");
			printf("现有隧道 %d 条\n", t->tunnel_num);

			pthread_mutex_unlock(&g_mutex_lock);
		}

		fd_set readFDSet;
		
		FD_ZERO(&readFDSet);
		FD_SET(tunfd, &readFDSet);
		//FD_SET(pipeTgetP, &readFDSet);
		/*
		tun 数据分配 不需要超时停止
		
		*/
		struct timeval timeout;
		timeout.tv_sec = 1; // 1秒超时
		timeout.tv_usec = 0;
		int select_ret = select(FD_SETSIZE, &readFDSet, NULL, NULL, &timeout);
		printf("select_ret %d \n",select_ret);
		if(select_ret == 0) //超时，判断是否存在新的隧道
		{
			printf(" tun 无数据到来\n");
			continue;
		}
		 	
		//printf("\nserver pthread select_ret: %d\n",select_ret);

		if (FD_ISSET(tunfd, &readFDSet)) // tun 中有数据
		{
			// 取出数据并检查确认数据归属
			/*
			int tunnel_num = 0;
			int pipefd = t->tunnel_infos[tunnel_num].pipefd; // 对应进程的pipe 描述符
			*/
			printf("\n数据分配\n");
			int len;
			char buff[BUFF_SIZE];
			int pipefd = -1;
			bzero(buff, BUFF_SIZE);
			
			// 读出数据
			len = read(tunfd, buff, BUFF_SIZE);

			if(len >0)
			{
				//展示信息
				printf("数据分配器 数据包长度:%d\n",len);
				tunnel_info tunnelinfo;

				
				ipheader * iph = (ipheader*)buff;
				//memcpy(&(tunnelinfo.iph_destip), &(iph->iph_destip), sizeof(iph->iph_destip));
			
				tcpheader* tcph = (tcpheader*)(buff+sizeof(ipheader));
				//memcpy(&(tunnelinfo.tcp_dport),&(tcph->tcp_dport),sizeof(tcph->tcp_dport));

				printf("dst ip %s, dsport %d\n",inet_ntoa(iph->iph_destip),ntohs(tcph->tcp_dport));


				for(int i =0; i <TUNNEL_NUM;i++)
				{
					//
					if(t->tunnel_infos[i].chilid_pid != 0 && t->tunnel_infos[i].info_seted == 1) //隧道存在，转发信息获取
					{
						printf("隧道 对端 ip: %s\n",inet_ntoa(t->tunnel_infos[i].iph_destip));

						if(t->tunnel_infos[i].iph_destip.s_addr == iph->iph_destip.s_addr)
						{// 地址相同
							pipefd =  t->tunnel_infos[i].pipefd;
							printf("数据包转发给 隧道序号 %d pid %d\n",i,t->tunnel_infos[i].chilid_pid);
							goto  write_into_pipe;
						}
					}

				}

				
				write_into_pipe:
				if(pipefd!= -1)
				{
					write(pipefd,buff,len); //写入pipe
				}
				else
				{
					// 如果找不到合适的隧道，直接丢弃数据包，等待重传吧
					printf("未找到合适的隧道分发数据\n");

				}
				
				

			}
			else if(len == 0)
			{			
				printf("读出数据长度为0\n");
				//return 0;
			}
		}

		
	}
	return NULL;
}

// 负责完善 隧道信息
void* tunnel_info_patch(void *TUNNELS)
{
	tunnels * tunnels =(struct tunnels *) TUNNELS;
	int pipeGetchild = open(GlobalPIPE,O_RDONLY); // 阻塞
	while (1)
	{
		

		infoP2T info;
		memset(&info,0,sizeof(infoP2T));
		int len = read(pipeGetchild,&info,sizeof(infoP2T)); // 阻塞读

		if(len)
		{	
			printf("---------------thread隧道信息反馈处理----------------\n");


			for(int i =0; i<TUNNEL_NUM;i++) // 寻找对应的隧道
			{
				if(info.chilid_pid == tunnels->tunnel_infos[i].chilid_pid)// 子进程号 对应
				{
					if(info.func == 1) // 创建隧道
					{  
						printf("创建隧道\n");
						memcpy(&(tunnels->tunnel_infos[i].iph_destip),&(info.iph_destip),sizeof(info.iph_destip));
						memcpy(&(tunnels->tunnel_infos[i].tcp_dport),&(info.tcp_dport),sizeof(info.tcp_dport));
						tunnels->tunnel_infos[i].info_seted = 1;
						printf("设置反向转发路径  pid: %d, dst ip: %s\n",tunnels->tunnel_infos[i].chilid_pid,
									inet_ntoa(tunnels->tunnel_infos[i].iph_destip));

						pthread_mutex_lock(&g_mutex_lock);
						tunnels->info_all_seted = 1; 
						tunnels->tunnel_num++;  //隧道数量 增加
						pthread_mutex_unlock(&g_mutex_lock);

					}
					else if(info.func == 2 )
					{
						close(tunnels->tunnel_infos[i].pipefd); // 关闭pipefd
						memset(&(tunnels->tunnel_infos[i]),0,sizeof(tunnels->tunnel_infos[i])); //清空隧道信息

						pthread_mutex_lock(&g_mutex_lock);
						tunnels->tunnel_num--; // 隧道销毁
						pthread_mutex_unlock(&g_mutex_lock);

					}
					else if(info.func == 3)
					{
						
					}
					
				}
			}	
		}
	}
	close(pipeGetchild);
	return NULL;
}

int check_id(int sockfd)
{

	//int len  = read(sockfd,);

	return 1;
} 




int combind_vpn_tls_server(int argc, char *argv[])
{
	
	tunnels tunnels;
	//pthread_rwlock_init(&myrwlock, NULL);
	int ret = pthread_mutex_init(&g_mutex_lock, NULL);
    if (ret != 0) {
        printf("mutex init failed\n");
        return -1;
    }
	memset(&tunnels,0,sizeof(tunnels)); // 清空隧道信息

	tunnels.tunnel_num =0;
	tunnels.info_all_seted =0;

	//daemon(1, 1);// 守护进程
	int mkfifo_res =mkfifo(GlobalPIPE,0666);
	if (mkfifo_res < 0) {
		printf("\ncreate GlobalPIPE fifo failure\n");
	}
	else
	{
		printf("\ncreate  GlobalPIPE fifo success\n");
	}
	

	tunfd = createTunDevice();// 建立tun
	system("sudo ifconfig tun0 192.168.53.1/24 up"); // 配置服务器tun
	printf("sudo ifconfig tun0 192.168.53.1/24 up\n");
	

	SSL *ssl = setupTLSServer();

	struct sockaddr_in sa_client;
	size_t client_len = sizeof(sa_client);

	int listen_sock = setupTCPServer(); // 建立连接使用socket

	fprintf(stderr, "TCP监听中..... listen_sock = %d\n", listen_sock);

	pthread_t tid1,tid2;
	pthread_create(&tid1,NULL,setup_tun_data_distributor,(void *)&tunnels);
	pthread_create(&tid2,NULL,tunnel_info_patch,(void *)&tunnels);


	while (1) {
	// 建立连接
		int sockfd = accept(listen_sock, (struct sockaddr *) &sa_client, &client_len);// 新的socket
		if (sockfd == -1) {
			//fprintf(stderr, "Accept TCP connect failed! (%d: %s)\n", errno, strerror(errno));
			printf(" TCP 连接失败 \n");
			continue;
		}

		pthread_mutex_lock(&g_mutex_lock);
		tunnels.info_all_seted = 0;
		pthread_mutex_unlock(&g_mutex_lock);

		int tunnel_exist = -1;	
		for(int i =0; i<TUNNEL_NUM;i++)
		{
			if(tunnels.tunnel_infos[i].chilid_pid == 0)
			 	tunnel_exist = i; //选择一个空隧道表项
		}
		
		if (tunnel_exist == -1)
		{
			printf("隧道数量受限！连接失败！\n"); // 等待隧道空余
			continue;
		}

		int pid = fork();
		
		if(pid)
		{	// 主进程 
			close(sockfd); // 关闭建立连接的socket
			char pid_str[10] ="";
			//itoa(pid,pid_str,10);
			sprintf(pid_str,"%d",pid);
			//printf("-----------pid =%d, pid_str=%s-------------\n",pid,pid_str);

			char *pipefilename = (char *) malloc(strlen(PIPE) + strlen(pid_str)+1);
			sprintf(pipefilename , "%s%s", PIPE,pid_str);
			//printf("-----------pipe filename: %s-----------\n",pipefilename);

			int mkfifo_res =mkfifo(pipefilename,0666);
			if (mkfifo_res < 0) {
        		printf("\nchildproc  create fifo failure\n");
			}
			else
			{
    			printf("\nchildproc create fifo success\n");
			}

			int pipefd = open(pipefilename, O_WRONLY );

			//char hello[] = "hello, my child\n";
			//write(pipefd,hello,strlen(hello));
			
			//配置隧道信息
			tunnels.tunnel_infos[tunnel_exist].chilid_pid = pid;
			memcpy(tunnels.tunnel_infos[tunnel_exist].pipefilename, pipefilename, strlen(pipefilename)+1);
			tunnels.tunnel_infos[tunnel_exist].pipefd = pipefd;
		}
		else if (pid == 0) {	// The child process

			close(listen_sock);// 关闭监听的socket
			
			if(check_id(sockfd) == 0) // 验证失败退出
			{
				// 销毁隧道记录
					infoP2T tunnelinfo;
					tunnelinfo.chilid_pid = getpid();
					tunnelinfo.func = 3;

					int pipeP2T = open(GlobalPIPE, O_WRONLY );
					write(pipeP2T,&tunnelinfo,sizeof(tunnelinfo)); // 传给隧道信息管理线程
					close(pipeP2T); // 关闭写入口

				exit(0);
			}
				




			SSL_set_fd(ssl, sockfd);
			int err = SSL_accept(ssl);
			
			//fprintf(stderr, "SSL_accept return %d\n", err);
			CHK_SSL(err);
			printf("\nSSL connection established!\n");
			

			// 进程信息和管道信息
			char pid_str[10] ="";
			pid = getpid();
			sprintf(pid_str,"%d",pid);
			char *pipefilename = (char *) malloc(strlen(PIPE) + strlen(pid_str)+1);
			sprintf(pipefilename , "%s%s", PIPE,pid_str);
			
			char buf[30];
			int pipefd = open(pipefilename, O_RDONLY);

			while (1) {
				fd_set readFDSet;

				FD_ZERO(&readFDSet);
				FD_SET(sockfd, &readFDSet);
				FD_SET(pipefd, &readFDSet);

				struct timeval timeout;
				timeout.tv_sec = TIMEOUT; // 5秒超时
    			timeout.tv_usec = 0;

				int select_ret = select(FD_SETSIZE, &readFDSet, NULL, NULL, &timeout);
				//printf("\nserver child process select_ret: %d\n",select_ret);
				
				if(select_ret <= 0) 
				{
					//processRequest(ssl, sockfd);
					exit_server_cproc:
					SSL_shutdown(ssl);
					SSL_free(ssl);
					close(sockfd);
					close(pipefd);
					
					int del_fifo = unlink(pipefilename); // 关闭有名管道
					// 判断是否成功删除管道
					if (del_fifo == -1)
					{
						printf("\nunlink %s failed\n", pipefilename);
						return -1;
					}
					else
					{
						printf("\nunlink %s success\n", pipefilename);
					}

					// 销毁隧道记录
					infoP2T tunnelinfo;
					tunnelinfo.chilid_pid = getpid();
					tunnelinfo.func = 2;

					int pipeP2T = open(GlobalPIPE, O_WRONLY );
					write(pipeP2T,&tunnelinfo,sizeof(tunnelinfo)); // 传给隧道信息管理线程
					close(pipeP2T); // 关闭写入口


					printf("\n服务器连接子进程 %d退出 \n",pid);
					exit(0);

				}

				if (FD_ISSET(pipefd, &readFDSet)) // pipe 中传来 tun数据
				{
					// need to change
					//tun_tls_Selected(tunfd, ssl); // 从tun中取出，传入socket，进入 docker1
					pipe_tls_Selected(pipefd,ssl);
				}

				if (FD_ISSET(sockfd, &readFDSet))// socket 中有数据,即 SSL 连接有数据
				{
					if(socket_tls_Selected(ssl,tunfd)== 0) // 表示连接中断
					{
						goto exit_server_cproc;
					}
					
					 // 从socket 中取出数据，传入tun
				}
				
			}
			

		}
	}
	//pthread_rwlock_destroy(&myrwlock); // 销毁读写锁
	pthread_mutex_destroy(&g_mutex_lock);
	return 0;

}

int main(int argc, char *argv[])
{
	combind_vpn_tls_server(argc, argv);
}


