all: vpn_tls_server.c vpn_tls_client.c
	gcc -o vpn_tls_server vpn_tls_server.c -lcrypto -lssl -lpthread -lcrypt
	gcc -o vpn_tls_client vpn_tls_client.c -lcrypto -lssl -lpthread -lcrypt


clean:
	rm -f vpn_tls_server vpn_tls_client
	rm -f *~
	rm -f pipe/*