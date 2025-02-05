from scapy.all import sniff, IP, TCP
import os
from collections import defaultdict
import time
import logging

# Configure logging
logging.basicConfig(filename="idps.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Dictionary to track connection attempts
connection_attempts = defaultdict(list)
THRESHOLD = 10  # Number of packets per second before flagging as malicious
BLOCKED_IPS = set()

def block_ip(ip):
    if ip not in BLOCKED_IPS:
        logging.info(f"Blocking IP: {ip}")
        print(f"[!] Blocking IP: {ip}")
        BLOCKED_IPS.add(ip)
        
        # Block IP using firewall rules (Linux: iptables, Windows: netsh)
        if os.name == "posix":
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        elif os.name == "nt":
            os.system(f"netsh advfirewall firewall add rule name='Block {ip}' dir=in action=block remoteip={ip}")

def detect_intrusion(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        timestamp = time.time()
        
        connection_attempts[ip_src].append(timestamp)
        
        # Remove outdated attempts (older than 1 sec)
        connection_attempts[ip_src] = [t for t in connection_attempts[ip_src] if timestamp - t < 1]
        
        if len(connection_attempts[ip_src]) > THRESHOLD:
            logging.warning(f"Potential attack detected from {ip_src}")
            print(f"[ALERT] Potential attack detected from {ip_src}!")
            block_ip(ip_src)
        
        # Detect SYN Flood Attack
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN flag set
            logging.warning(f"SYN Flood detected from {ip_src}")
            print(f"[ALERT] SYN Flood detected from {ip_src}")
            block_ip(ip_src)
        
        # Detect brute-force attempts (many connections to different ports)
        unique_ports = {packet[TCP].dport for packet in connection_attempts[ip_src] if packet.haslayer(TCP)}
        if len(unique_ports) > 5:
            logging.warning(f"Brute-force attempt detected from {ip_src}")
            print(f"[ALERT] Brute-force attempt detected from {ip_src}")
            block_ip(ip_src)

def start_monitoring():
    logging.info("Intrusion Detection & Prevention System Started")
    print("[*] Intrusion Detection & Prevention System Running...")
    sniff(filter="tcp", prn=detect_intrusion, store=False)

if __name__ == "__main__":
    start_monitoring()
