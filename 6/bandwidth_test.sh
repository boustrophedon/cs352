#!/bin/bash

pipenv run python2 enc_bw_test.py -s -f enc_bw_test.py -d localhost -p 9999 -l 8888 -k keyfile.txt &
serv_pid=$!
sleep 0.5
pipenv run python2 enc_bw_test.py -d localhost -p 8888 -l 3333 -f enc_client_1.py -k keyfile.txt
