#!/usr/bin/env bash

IFACE=eth0
IP=`ifconfig ${IFACE} | grep inet | cut -d':' -f2 | cut -d' ' -f1`

rmmod iproxy-server &> /dev/null
insmod iproxy-server.ko local_ip=${IP} local_port=2357 vip_start=10.0.0.0 vip_number=100
