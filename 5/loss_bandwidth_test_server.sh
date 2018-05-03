#!/bin/bash

python2 rel_bw_test.py -s -f rel_bw_test.py -d localhost -p 4000 -l 5000 &
serv_pid=$!
sleep 0.5

cd test_code
python2 rel_bw_test.py -d localhost -p 5000 -l 3333 -f rel_client_1.py
