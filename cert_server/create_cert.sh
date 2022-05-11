#!/bin/sh
#rm -f demoCA/index.txt
openssl req -new -nodes -keyout /tmp/key.pem -out /tmp/req.pem -config openssl.cnf 
openssl ca -policy policy_anything -config openssl.cnf -days 365 -out server.crt -in /tmp/req.pem -cert ca.crt -keyfile ca.key
openssl rsa -in /tmp/key.pem -out server.key
