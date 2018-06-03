# iproxy
IP Proxy - IP Layer Proxy

## Compile
### Server Side
```
cd src
make m=server
make tool m=server
```
### Client Side
```
cd src
make m=client
make tool m=client
```

## Server Side Start
```
cd src
../script/set-net.sh
../script/set-iptables.sh
../script/start-server.sh
```

## Client Side Start
```
cd src
../script/start-client.sh
```
