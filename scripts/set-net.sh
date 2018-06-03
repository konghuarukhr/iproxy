#!/usr/bin/env bash

# https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
sysctl net.ipv4.conf.all.rp_filter=0
sysctl net.ipv4.conf.all.accept_local=1
sysctl net.ipv4.ip_forward=1
sysctl net.ipv4.ip_local_reserved_ports=2357
