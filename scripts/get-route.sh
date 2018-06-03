#!/usr/bin/env bash

# Change to current directory
cd `dirname $0`


# $1: msg
log() {
	echo "$TODAY:`date +%H%M%S`: " $@ >> ${TODAY_LOG_FILE} 2>&1
}

# $1: test result; $2: failed msg
check() {
	if [ "$1" != "0" ]; then
		log "$2"
		log "exit"
		exit -1
	fi
}


TODAY=`date +%Y%m%d`
YESTERDAY=`date -d "yesterday" +%Y%m%d`
BEFORE_YESTERDAY=`date -d "-2 days" +%Y%m%d`

ROUTE_FILE=delegated-apnic
LOG_FILE=run
TODAY_ROUTE_FILE=${ROUTE_FILE}-${TODAY}.dat
TODAY_ROUTE_FILE_MD5=${ROUTE_FILE}-${TODAY}.md5
TODAY_LOG_FILE=${LOG_FILE}-${TODAY}.log
YESTERDAY_ROUTE_FILE=${ROUTE_FILE}-${YESTERDAY}.dat
YESTERDAY_ROUTE_FILE_MD5=${ROUTE_FILE}-${YESTERDAY}.md5
YESTERDAY_LOG_FILE=${LOG_FILE}-${YESTERDAY}.log
BEFORE_YESTERDAY_ROUTE_FILE=${ROUTE_FILE}-${BEFORE_YESTERDAY}.dat
BEFORE_YESTERDAY_ROUTE_FILE_MD5=${ROUTE_FILE}-${BEFORE_YESTERDAY}.md5
BEFORE_YESTERDAY_LOG_FILE=${LOG_FILE}-${BEFORE_YESTERDAY}.log
CHINA_ROUTE_FILE=china-ipv4.dat

log "--------------------------------"

# Download new files
log "downloading..."
wget -qO ${TODAY_ROUTE_FILE} 'https://ftp.apnic.net/stats/apnic/delegated-apnic-latest'
check $? "download data error"
wget -qO ${TODAY_ROUTE_FILE_MD5} 'https://ftp.apnic.net/stats/apnic/delegated-apnic-latest.md5'
check $? "download MD5 error"
log "downloaded"

# Check downloaded files
STD_MD5=`cut -d " " -f 4 ${TODAY_ROUTE_FILE_MD5}`
MD5=`md5sum ${TODAY_ROUTE_FILE} | cut -d " " -f 1`
test "${MD5}" == "${STD_MD5}"
check $? "MD5 error"
log "MD5 OK"

# Generate China IPv4 file
#grep "^apnic|CN|ipv4" ${TODAY_ROUTE_FILE} | cut -d"|" -sf"4,5" > ${CHINA_ROUTE_FILE}
#echo "x=0;for(y=$n;y>0;y/=2)x+=1;33-x" | bc
awk -F '|' '/^apnic\|CN\|ipv4/{y=0;for(x=1;x<$5;x*=2)y++;y=32-y;print $4"/"y}' ${TODAY_ROUTE_FILE} >  ${CHINA_ROUTE_FILE}
log "china route file generated"

# Delete old files
if [ -f ${BEFORE_YESTERDAY_ROUTE_FILE} ]; then
	rm -f ${BEFORE_YESTERDAY_ROUTE_FILE}
fi
if [ -f ${BEFORE_YESTERDAY_ROUTE_FILE_MD5} ]; then
	rm -f ${BEFORE_YESTERDAY_ROUTE_FILE_MD5}
fi
if [ -f ${BEFORE_YESTERDAY_LOG_FILE} ]; then
	rm -f ${BEFORE_YESTERDAY_LOG_FILE}
fi
