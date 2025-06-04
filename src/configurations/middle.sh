#!/bin/bash
set -x

#asta lipsea din fisierul initial, a trebuit sa il adaug dupa ce am citit complet cerintele/documentatia din README
sysctl -w net.ipv4.ip_forward=1

# add route to subnet 198.7.0.0/16 via IP 172.7.0.1
ip route add 172.7.0.0/16 via 198.7.0.1

# add 8.8.8.8 nameserver
echo "nameserver 8.8.8.8" >> /etc/resolv.conf

# we need to drop the kernel reset of hand-coded tcp connections
# https://stackoverflow.com/a/8578541
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

# and redirect incoming traffic
# https://my.esecuredata.com/index.php?/knowledgebase/article/49/how-to-redirect-an-incoming-connection-to-a-different-ip-address-on-a-specific-port-using-iptables/
iptables -t nat -A POSTROUTING -j MASQUERADE 

# simulez cum functioneaza pachetele in viata reala
tc qdisc add dev eth0 root netem delay 100ms 10ms 25% loss 5% 25% corrupt 10% reorder 25% 50%

