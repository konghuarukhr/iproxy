#!/bin/bash

pgm=../src/route-cli
data=../scripts/china-ipv4.dat

for i in `seq 1000`; do
{
	$pgm load $data && sleep 0.99 && $pgm show > /dev/null
}&
done
