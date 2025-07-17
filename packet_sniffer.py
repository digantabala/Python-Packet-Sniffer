from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, conf
import argparse
import sys
import signal

# Handle CTRL+C gracefully
def signal_handler(sig, frame):
    print("\n[!] Sniffer stopped.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def get_protocol_name(layer):
    """Map protocol layers to human-readable names"""
    return {
        TCP: "TCP",
        UDP: "UDP",
        ICMP: "ICMP",
        ARP: "ARP",
        IP: "IP"
    }.get(layer, "Unknown")

def format_payload(payload, max_len=64):
    """Format payload data safely"""
    printable = ''.join(
        chr(byte) if 32 <= byte <= 126 else '.' 
        for byte in payload[:max_len]
    )
    return f"{printable} [Truncated]" if len(payload) > max_len else printable

def process_packet(packet):
    """Process and display packet information"""
    # Skip packets without network layer info
    if not (packet.haslayer(IP) or packet.haslayer(ARP)):
        return
    
    # Basic information
    timestamp = packet.time
    protocol = None
    src_ip, dst_ip = "N/A", "N/A"
    src_port, dst_port = "N/A", "N/A"
    payload_data = ""
    
    # Ethernet frame details
    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
    
    # IP layer processing
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Transport layer processing
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            if packet[TCP].payload:
                payload_data = bytes(packet[TCP].payload)
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            if packet[UDP].payload:
                payload_data = bytes(packet[UDP].payload)
    
    # ARP processing
    elif packet.haslayer(ARP):
        protocol = "ARP"
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
    
    # Protocol identification
    protocol_name = get_protocol_name(packet.payload.__class__)
    
    # Display results
    print(f"\n[+] Timestamp: {timestamp:.6f}")
    print(f"    Protocol: {protocol_name} (ID: {protocol})" if protocol else f"    Protocol: {protocol_name}")
    print(f"    Source: {src_ip}:{src_port}" if src_port != "N/A" else f"    Source: {src_ip}")
    print(f"    Target:  {dst_ip}:{dst_port}" if dst_port != "N/A" else f"    Target:  {dst_ip}")
    
    if payload_data:
        print(f"    Payload: {format_payload(payload_data)}")

def main():
    parser = argparse.ArgumentParser(
        description="Educational Packet Sniffer - Use ethically and legally!",
        epilog="WARNING: Unauthorized network monitoring is illegal in most jurisdictions."
    )
    parser.add_argument("-i", "--interface", help="Network interface (e.g., eth0)", default=conf.iface)
    parser.add_argument("-c", "--count", help="Number of packets to capture (0=unlimited)", type=int, default=0)
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp port 80')", default="")
    
    args = parser.parse_args()
    
    print(f"[*] Starting packet sniffer on {args.interface}")
    print(f"[*] Filter: {args.filter if args.filter else 'None'}")
    print("[*] Ethical reminder: Only capture traffic on networks you own!")
    print("[*] Press CTRL+C to stop\n")
    
    # Start sniffing with configurable parameters
    sniff(
        iface=args.interface,
        filter=args.filter,
        prn=process_packet,
        count=args.count,
        store=0  # Don't store packets in memory
    )

if __name__ == "__main__":
    main()