#/bin/python3

import scapy.all as scapy




def packet_callback(packet):
	if packet.haslayer(scapy.IP):
		ip_src = packet[scapy.IP].src
		ip_dst = packet[scapy.IP].dst
		print(f"IP Scorce: {ip_src}, IP Destination: {ip_dst}")
		
		if packet.haslayer(scapy.TCP):
			tcp_src_port = packet[scapy.TCP].sport
			tcp_dst_port = packet[scapy.TCP].dport
			print(f"TCP Scorce Port: {tcp_src_port}, TCP Destination Port: {tcp_dst_port}")
			
		elif packet.haslayer(scapy.UDP):
			udp_src_port = packet[scapy.UDP].sport
			udp_dst_port = packet[scapy.UDP].dport
			print(f"UDP Scorce Port: {udp_src_port}, UDP Destination Port: {udp_dst_port}")
		
		elif packet.haslayer(scapy.ICMP):
			icmp_src_port = packet[scapy.ICMP].sport
			icmp_dst_port = packet[scapy.ICMP].dport
			print(f"ICMP Scorce Port: {icmp_src_port}, ICMP Destination Port: {icmp_dst_port}")
			
#select your interface (eth0, wlan0, Wi-Fi)			
network_interface = 'eth0'

scapy.sniff(iface=network_interface, store=False, prn=packet_callback)
