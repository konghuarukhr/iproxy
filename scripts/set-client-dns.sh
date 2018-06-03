#!/usr/bin/env bash

iptables -tnat -AOUTPUT -pudp --dport 53 -jDNAT --to-destination 8.8.4.4
iptables -tnat -APREROUTING -pudp --dport 53 -jDNAT --to-destination 8.8.4.4
iptables -tnat -APOSTROUTING -o enp0s3 -j MASQUERADE
