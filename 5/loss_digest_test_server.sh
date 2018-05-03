#!/bin/bash

python2 rel_server_1.py -l 5000 >out/loss_digest_server.txt &
serv_pid=$!
sleep 0.5
cd test_code
python2 rel_client_1.py -d localhost -p 5000 -l 3333 -f rel_client_1.py -z 0.4 >out/loss_digest_client.txt

tail out/loss_digest_client.txt
