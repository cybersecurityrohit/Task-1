from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
import socket
import os


output_file_path = "C:/python/Task1/captured_packets.txt" 


output_file = open(output_file_path, "a")
packet_counter = 0  

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def packet_callback(packet):
    global packet_counter
    packet_counter += 1

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output_file.write(f"\n[{timestamp}] Packet #{packet_counter}\n")
    print(f"\n[{timestamp}] Packet #{packet_counter}")

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        size = len(packet)

        src_host = get_hostname(src_ip)
        dst_host = get_hostname(dst_ip)

        info = f"""    Source IP: {src_ip} ({src_host})
    Destination IP: {dst_ip} ({dst_host})
    Protocol: {proto}
    Packet Size: {size} bytes"""

        print(info)
        output_file.write(info + "\n")

        if TCP in packet:
            tcp_layer = packet[TCP]
            tcp_info = f"""    TCP Segment:
        Source Port: {tcp_layer.sport}
        Destination Port: {tcp_layer.dport}\n"""
            print(tcp_info)
            output_file.write(tcp_info)

        elif UDP in packet:
            udp_layer = packet[UDP]
            udp_info = f"""    UDP Segment:
        Source Port: {udp_layer.sport}
        Destination Port: {udp_layer.dport}\n"""
            print(udp_info)
            output_file.write(udp_info)

print("[*] Starting Scapy-based Network Sniffer... Press Ctrl+C to stop.")
try:
    sniff(prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\n[*] Sniffing stopped by user.")
finally:
    output_file.close()
    print(f"[*] Output saved to {output_file_path}")


    if os.path.isfile(output_file_path):
        print(f"[*] Log file successfully created: {os.path.abspath(output_file_path)}")
    else:
        print("[!] Log file not found!")
