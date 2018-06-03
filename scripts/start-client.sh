#!/usr/bin/env bash

rmmod iproxy-client &> /dev/null
insmod iproxy-client.ko server_ip=<A.B.C.D> server_port=2222
