#!/bin/bash

python2 rel_server_1.py -l 5000 >out/digest_server.txt &
serv_pid=$!
sleep 0.5
python2 rel_client_1.py -d localhost -p 5000 -l 3333 -f rel_client_1.py >out/digest_client.txt

tail out/digest_client.txt
