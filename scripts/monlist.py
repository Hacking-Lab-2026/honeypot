#!/usr/bin/env python3
"""Send an SSDP M-SEARCH request and inspect the response."""

import socket
import sys

def send_msearch(host, port=1900, timeout=3):
    request = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {host}:{port}\r\n"
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
            data, addr = sock.recvfrom(4096)
            # Only keep replies from the host we queried — filters out LAN
            # devices (routers, printers) that also answer M-SEARCH.
            if addr[0] == host:
                packets.append(data)
            else:
                print(f"  (ignored reply from {addr[0]} — not the target)")
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
    print(f"Received {len(packets)} packet(s) from {host}, {total_bytes} total bytes")
    if total_bytes:
        print(f"Amplification factor: {total_bytes / 84:.1f}x (request was ~84 bytes)")
    print()

    for i, p in enumerate(packets):
        print(f"--- Packet {i} ({len(p)} bytes) ---")
        print(p.decode(errors="replace"))