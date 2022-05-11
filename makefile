all: vpn_tls_server.c vpn_tls_client.c
	gcc -o vpn_tls_server vpn_tls_server.c -lcrypto -lssl
	gcc -o vpn_tls_client vpn_tls_client.c -lcrypto -lssl


clean:
	rm -f vpn_tls_server vpn_tls_client
	rm -f *~