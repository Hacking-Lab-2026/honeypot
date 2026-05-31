import socket
import struct
import sys

def send_ntp_mode(target_host, target_port, mode, description):
    """Send an NTP packet with a specific mode."""
    # NTP packet header: LI(2) VN(3) Mode(3) + other fields
    li = 0  # leap indicator
    vn = 4  # version number
    pkt = bytearray(48)
    
    # Byte 0: LI(2) | VN(3) | Mode(3)
    pkt[0] = (li << 6) | (vn << 3) | (mode & 0x7)
    pkt[1] = 2  # stratum
    pkt[2] = 6  # poll
    pkt[3] = 0xEC  # precision
    
    # Send from a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(bytes(pkt), (target_host, target_port))
    sock.close()
    
    print(f"[+] Sent NTP mode {mode} ({description}) to {target_host}:{target_port}")

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 123
    
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    
    send_ntp_mode(host, port, 4, "Server")
    send_ntp_mode(host, port, 6, "Control")
    send_ntp_mode(host, port, 7, "Monlist/Amplification")