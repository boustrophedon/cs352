#!/bin/bash
pipenv run python2 enc_server_1.py -l 9999 -k keyfile.txt >out/digest_server.txt &
serv_pid=$!
sleep 0.5

pipenv run python2 enc_client_1.py -d localhost -p 9999 -l 8888 -f enc_client_1.py -k keyfile.txt >out/digest_client.txt

tail out/digest_client.txt
