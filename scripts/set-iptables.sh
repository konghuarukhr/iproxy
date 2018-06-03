#!/usr/bin/env bash

# output interface
IFACE=eth0
IP=`ifconfig ${IFACE} | grep inet | cut -d':' -f2 | cut -d' ' -f1`
MTU=`ifconfig ${IFACE} | grep MTU | cut -d':' -f2 | cut -d' ' -f1`
# 1500 - sizeof(iphdr) - sizeof(tcphdr) - sizeof(struct udphdr) - sizeof(struct iprhdr) == 1500 - 20 - 20 - 8 - 8 == 1444
MSS=`expr ${MTU} - 20 - 20 - 8 - 8`

iptables -tnat -DPOSTROUTING -o${IFACE} ! -s${IP} -ptcp --tcp-flags SYN,RST SYN -jTCPMSS --set-mss ${MSS} &> /dev/null
iptables -tnat -APOSTROUTING -o${IFACE} ! -s${IP} -ptcp --tcp-flags SYN,RST SYN -jTCPMSS --set-mss ${MSS}

iptables -tmangle -DPOSTROUTING -o${IFACE} ! -s${IP} -jTTL --ttl-set 128 &> /dev/null
iptables -tmangle -APOSTROUTING -o${IFACE} ! -s${IP} -jTTL --ttl-set 128

iptables -tnat -DPOSTROUTING -o${IFACE} ! -s${IP} -jSNAT --to-source ${IP} &> /dev/null
iptables -tnat -APOSTROUTING -o${IFACE} ! -s${IP} -jSNAT --to-source ${IP}
