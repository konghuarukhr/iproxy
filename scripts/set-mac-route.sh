#!/usr/bin/env bash

netstat -nrf inet
route delete default
route add default 10.1.1.129
