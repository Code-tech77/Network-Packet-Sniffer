import socket
import struct
import sys
import os

def parse_ipv4_header(data):
    version_header_len = data[0]
    header_len = (version_header_len & 15) * 4
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    proto = ip_header[6]
    return src_ip, dst_ip, proto, data[header_len:]

protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

def main():
    if os.name != 'nt':
        print("This script is designed for Windows.")
        return

    try:
        host = socket.gethostbyname(socket.gethostname())
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        print(f"Sniffing on: {host} — Press Ctrl+C to stop.\n")

        while True:
            raw_data, _ = sniffer.recvfrom(65535)
            src, dst, proto, _ = parse_ipv4_header(raw_data)
            print(f"[IPv4] {src} -> {dst} | Protocol: {protocols.get(proto, str(proto))}")

    except KeyboardInterrupt:
        print("\nSniffing stopped.")
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sniffer.close()

    except Exception as e:
        print(f"Error: {e}")
        if 'sniffer' in locals():
            try:
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                sniffer.close()
            except:
                pass

if __name__ == "__main__":
    main()
