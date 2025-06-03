FROM snisioi/retele:2021

RUN apt-get update && apt-get install -y iptables iproute2 libnetfilter-queue-dev whois

RUN pip3 install --upgrade python-iptables cython scapy

RUN mkdir -p /scripts

