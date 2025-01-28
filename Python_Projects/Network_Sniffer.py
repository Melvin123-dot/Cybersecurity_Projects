import os
from scapy.all import sniff, IP, TCP, UDP, Raw, wrpcap
from datetime import datetime

# Initialize an empty list to store captured packets
captured_packets = []

# Define an absolute directory to save the pcap file (using the user's "Documents" folder as an example)
save_directory = r"C:\Users\Lenovo\Desktop\Folders\My_Basic_To_Advanced_Python_Projects\captured_network_traffic"

def packet_callback(packet):
    """
    Callback function to process and analyze captured packets.
    """
    global captured_packets

    if IP in packet:
        # Extract IP layer information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Source IP: {src_ip} -> Destination IP: {dst_ip} | Protocol: {protocol}")

        # Check for TCP or UDP layers
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"  TCP: Source Port: {src_port}, Destination Port: {dst_port}")
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"  UDP: Source Port: {src_port}, Destination Port: {dst_port}")

        # Extract raw data if available
        if Raw in packet:
            raw_data = packet[Raw].load
            print(f"  Raw Data: {raw_data[:50]}...")  # Print first 50 bytes of raw data

        # Save packet to the list for later analysis or saving to a file
        captured_packets.append(packet)

        # Detect anomalies (e.g., repeated TCP SYN packets)
        if TCP in packet and packet[TCP].flags == "S":
            print("  Potential SYN scan detected!")

def save_captured_packets():
    """
    Save captured packets to a PCAP file.
    """
    if captured_packets:
        # Ensure the directory exists, if not, create it
        if not os.path.exists(save_directory):
            os.makedirs(save_directory)
        
        # Generate the filename with the current timestamp
        filename = os.path.join(save_directory, f"captured_traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
        
        # Save the captured packets to the specified file
        wrpcap(filename, captured_packets)
        print(f"\nCaptured packets saved to {filename}")
    else:
        print("\nNo packets were captured to save.")

def main():
    """
    Main function to start the enhanced network sniffer.
    """
    print("Starting network sniffer...\n")
    try:
        # Use sniff function to capture packets
        sniff(filter="ip", prn=packet_callback, store=False, timeout=60)  # Stop after 60 seconds
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")
    finally:
        save_captured_packets()

if __name__ == "__main__":
    main()
