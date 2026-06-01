#!/usr/bin/env python3
"""Send a monlist request and parse the response."""

import socket
import struct
import sys

def send_monlist(host, port=123, timeout=5):
    # Mode 7 monlist request: 8-byte header, no data
    # Byte 0: R=0, M=0, VN=2, Mode=7 -> 0x17
    # Byte 1: auth=0, seq=0
    # Byte 2: impl = 3 (IMPL_XNTPD)
    # Byte 3: req code = 42 (REQ_MON_GETLIST_1)
    # Bytes 4-7: err+items+mbz+itemsize, all zero for request
    request = bytes([0x17, 0x00, 0x03, 0x2A, 0x00, 0x00, 0x00, 0x00])
    
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

def parse_monlist_packet(data, idx):
    if len(data) < 8:
        print(f"  Packet {idx}: too short ({len(data)} bytes)")
        return
    
    b0 = data[0]
    response_flag = (b0 >> 7) & 1
    more_flag = (b0 >> 6) & 1
    vn = (b0 >> 3) & 0x7
    mode = b0 & 0x7
    
    seq = data[1] & 0x7F
    impl = data[2]
    req_code = data[3]
    err = (data[4] >> 4) & 0xF
    n_items = ((data[4] & 0xF) << 8) | data[5]
    item_size = ((data[6] & 0xF) << 8) | data[7]
    
    print(f"  Packet {idx}: {len(data)} bytes")
    print(f"    R={response_flag} M={more_flag} VN={vn} Mode={mode} Seq={seq}")
    print(f"    Impl={impl} ReqCode={req_code} Err={err} Items={n_items} ItemSize={item_size}")
    
    if err != 0:
        print(f"    ERROR code {err}")
        return
    
    # Parse items
    for i in range(n_items):
        offset = 8 + i * item_size
        if offset + item_size > len(data):
            print(f"    Item {i}: truncated")
            break
        item = data[offset:offset + item_size]
        firsttime = struct.unpack(">I", item[0:4])[0]
        lasttime = struct.unpack(">I", item[4:8])[0]
        count = struct.unpack(">I", item[12:16])[0]
        addr = ".".join(str(b) for b in item[16:20])
        port = struct.unpack(">H", item[28:30])[0]
        client_mode = item[30]
        client_vn = item[31]
        print(f"    Item {i}: addr={addr}:{port} mode={client_mode} vn={client_vn} count={count} first={firsttime}s last={lasttime}s")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 123
    
    print(f"Sending monlist to {host}:{port}...")
    packets = send_monlist(host, port)
    print(f"Received {len(packets)} packet(s)\n")
    
    for i, p in enumerate(packets):
        parse_monlist_packet(p, i)