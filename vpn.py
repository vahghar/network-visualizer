import fcntl
import struct
import os
import socket
import select
import sys
from cryptography.fernet import Fernet

# ================= CONFIGURATION =================
# PASTE YOUR GENERATED KEY HERE (Keep the b'' prefix!)
KEY = os.environ.get("secret_key").encode()

SERVER_IP = '127.0.0.1' # Localhost for testing
PORT = 55555
MTU = 1500
# =================================================

# Constants for Linux TUN/TAP
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

def create_tun_interface(dev_name='tun0'):
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', dev_name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    return tun_fd

def start_vpn(mode):
    # Initialize the Cipher Suite
    cipher = Fernet(KEY)
    
    tun_fd = create_tun_interface()
    print(f"[{mode.upper()}] Tunnel secure. Encryption enabled.")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    if mode == 'server':
        sock.bind(('0.0.0.0', PORT))
        client_addr = None
        print(f"Listening on UDP {PORT}...")
    else:
        server_addr = (SERVER_IP, PORT)
        # Send an encrypted Handshake to introduce ourselves
        handshake = cipher.encrypt(b'HANDSHAKE')
        sock.sendto(handshake, server_addr) 

    inputs = [sock, tun_fd]
    
    try:
        while True:
            ready, _, _ = select.select(inputs, [], [])

            for r in ready:
                # 1. OUTGOING: From OS (Plain) -> Encrypt -> To Internet
                if r == tun_fd:
                    packet = os.read(tun_fd, MTU)
                    
                    # ENCRYPT THE PACKET
                    token = cipher.encrypt(packet)
                    
                    if mode == 'client':
                        sock.sendto(token, server_addr)
                    elif mode == 'server' and client_addr:
                        sock.sendto(token, client_addr)

                # 2. INCOMING: From Internet (Encrypted) -> Decrypt -> To OS
                if r == sock:
                    token, addr = sock.recvfrom(MTU + 100) # Buffer slightly larger for overhead
                    
                    if mode == 'server':
                        if not client_addr or addr != client_addr:
                            client_addr = addr
                            print(f"New connection from {client_addr}")

                    try:
                        # DECRYPT THE PACKET
                        packet = cipher.decrypt(token)
                        
                        # Verify it's a real packet (not just a handshake)
                        if packet != b'HANDSHAKE':
                            os.write(tun_fd, packet)
                        else:
                            print("Handshake verified.")
                            
                    except Exception:
                        print(f"Dropped invalid/unencrypted packet from {addr}")

    except KeyboardInterrupt:
        os.close(tun_fd)
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 vpn.py [client|server]")
        sys.exit(1)
    start_vpn(sys.argv[1])