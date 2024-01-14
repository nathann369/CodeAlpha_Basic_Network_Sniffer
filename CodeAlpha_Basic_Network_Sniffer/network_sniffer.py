import scapy.all as scapy 
from scapy.layers import http

def sniffing(interface):
    scapy.sniff(iface=interface,store=False,prn=process_packet,filter='tcp')

def process_packet(packet):
    print(packet[http.HTTPRequest].Host)

#select your interface (eth0, wlan0, Wi-Fi)
sniffing('Eth0')