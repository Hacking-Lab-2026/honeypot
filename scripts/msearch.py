#!/usr/bin/env python3
import socket
import sys

def send_msearch(host, port=1900, timeout=3):
    request = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(request, (host, port))
    
    packets = []
    try:
        while True:
            data, _ = sock.recvfrom(4096)
            packets.append(data)
    except socket.timeout:
        pass
    sock.close()
    return packets

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1900
    
    print(f"Sending M-SEARCH to {host}:{port}...")
    packets = send_msearch(host, port)
    total_bytes = sum(len(p) for p in packets)
    print(f"Received {len(packets)} packet(s), {total_bytes} total bytes")
    print(f"Amplification factor: {total_bytes / 84:.1f}x (request was ~84 bytes)\n")
    for i, p in enumerate(packets):
        print(f"--- Packet {i} ({len(p)} bytes) ---")
        print(p.decode(errors="replace"))