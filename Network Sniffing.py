from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime

# A dictionary to store transaction history for each IP address
transaction_history = {}

def packet_callback(packet):
    # Extracting basic information from the packet
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        protocol = {6: "TCP", 17: "UDP"}.get(proto, "Other")
        
        if protocol == "TCP" and TCP in packet:
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
        elif protocol == "UDP" and UDP in packet:
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
        else:
            port_src = None
            port_dst = None

        # Printing the captured packet information
        print(f"Time: {datetime.now()} Source IP: {ip_src} Destination IP: {ip_dst} Protocol: {protocol} Source Port: {port_src} Destination Port: {port_dst}")

        # Updating transaction history
        update_transaction_history(ip_src, ip_dst, protocol, port_src, port_dst)

def update_transaction_history(src, dst, protocol, src_port, dst_port):
    transaction = {
        "time": datetime.now(),
        "src": src,
        "dst": dst,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port
    }
    
    if src not in transaction_history:
        transaction_history[src] = {"deposits": [], "withdrawals": []}
    if dst not in transaction_history:
        transaction_history[dst] = {"deposits": [], "withdrawals": []}

    # Assuming the 'src' is making a withdrawal and 'dst' is receiving a deposit
    transaction_history[src]["withdrawals"].append(transaction)
    transaction_history[dst]["deposits"].append(transaction)

def start_sniffing(interface):
    print(f"[*] Starting packet capture on {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)

def print_transaction_history():
    for ip, transactions in transaction_history.items():
        print(f"IP Address: {ip}")
        print("  Deposits:")
        for deposit in transactions["deposits"]:
            print(f"    Time: {deposit['time']} From: {deposit['src']} Protocol: {deposit['protocol']} Source Port: {deposit['src_port']} Destination Port: {deposit['dst_port']}")
        print("  Withdrawals:")
        for withdrawal in transactions["withdrawals"]:
            print(f"    Time: {withdrawal['time']} To: {withdrawal['dst']} Protocol: {withdrawal['protocol']} Source Port: {withdrawal['src_port']} Destination Port: {withdrawal['dst_port']}")

if __name__ == "main":
   
    interface = input("Enter the network interface to sniff (e.g., eth0, wlan0): ")
    
    try:
        start_sniffing(interface)
    except KeyboardInterrupt:
        print("\n[*] Stopping packet capture.")
        print_transaction_history()
        print("[*] Transaction history printed.")