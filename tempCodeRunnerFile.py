from scapy.all import sniff, Ether, get_if_list

def ethernet_frame(packet):
    if Ether in packet:
        eth = packet[Ether]
        dest_mac = eth.dst.upper()
        src_mac = eth.src.upper()
        eth_proto = hex(eth.type)
        return dest_mac, src_mac, eth_proto
    return None, None, None

def process_packet(packet):
    dest_mac, src_mac, eth_proto = ethernet_frame(packet)
    if dest_mac and src_mac and eth_proto:
        print("\nEthernet Frame:")
        print(f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

def main():
    print("Available Interfaces:")
    interfaces = get_if_list()
    for idx, iface in enumerate(interfaces):
        print(f"{idx}: {iface}")

    try:
        choice = int(input("Select interface number to sniff on: "))
        iface = interfaces[choice]
    except (IndexError, ValueError):
        print("Invalid selection.")
        return

    print(f"\nSniffing on: {iface}")
    print("Press Ctrl+C to stop...\n")
    
    sniff(iface=iface, prn=process_packet, store=False)

if __name__ == "__main__":
    main()
