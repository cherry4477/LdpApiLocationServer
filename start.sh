#!/bin/bash


#替换redis信息

sed -i 's/REDIS_SERVER_IP/'$REDIS_PORT_6379_TCP_ADDR'/g'  ./config/userQuery.conf
sed -i 's/REDIS_SERVER_PORT/'$REDIS_PORT_6379_TCP_PORT'/g'  ./config/userQuery.conf


./LdpLocation -c ./config/userQuery.conf -n location 

#nohup ./LdpLocation -c ./config/userQuery.conf -n location  /dev/null 2>&1 &
