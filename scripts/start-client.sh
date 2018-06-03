#!/usr/bin/env bash

rmmod iproxy-client &> /dev/null
insmod iproxy-client.ko server_ip=47.52.88.28 server_port=2357
