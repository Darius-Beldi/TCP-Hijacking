# TCP-Hijacking

## The container structure I used for testing:

```
            MIDDLE------------\
        subnet2: 198.7.0.3     \
        MAC: 02:42:c6:0a:00:02  \
               forwarding        \ 
              /                   \
             /                     \
Poison ARP 198.7.0.1 is-at         Poison ARP 198.7.0.2 is-at 
           02:42:c6:0a:00:02         |         02:42:c6:0a:00:02
           /                         |
          /                          |
         /                           |
        /                            |
    SERVER <---------------------> ROUTER <---------------------> CLIENT
net2: 198.7.0.2                      |                           net1: 172.7.0.2
MAC: 02:42:c6:0a:00:03               |                            MAC eth0: 02:42:ac:0a:00:02
                           subnet1:  172.7.0.1
                           MAC eth0: 02:42:ac:0a:00:01
                           subnet2:  198.7.0.1
                           MAC eth1: 02:42:c6:0a:00:01
                           subnet1 <------> subnet2
                                 forwarding
```

## Prerequisites
Linux based system
Install docker and docker-compose:
```
apt-get install docker docker-compose
```

## How to run

Create a docker image:

    cd Docker
    docker build -t tcp_hijacking
    
Start the containers

    docker-compose up -d

Run the spoofing script in a middle bash

    docker-compose exec middle bash
    python3 scripts/tcp_hijacking.py
    
### Clear the iptables for server and router containers 

In separate terminals:
```
docker-compose exec server bash
ip -s -s neigh flush all
```
```
docker-compose exec router bash
ip -s -s neigh flush all
```

## Testing
Open another two terminals, one for the client and one for the server. They will send each other messages.

```
docker-compose exec server bash
python3 scripts/tcp_server.py
```

```
docker-compose exec client bash
python3 scripts/tcp_client.py
```

### Outcome
In the two terminals, server and client you should see the altered messages while in the middle terminal you should see that the messages are being hijacked
![image](https://github.com/user-attachments/assets/fabb9dbc-72f3-497e-8471-98d20a458c6e)
