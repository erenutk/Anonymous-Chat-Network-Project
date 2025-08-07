import argparse
from scapy.all import IP, UDP, Raw, Ether, sendp, RandMAC, RandShort
import random
import sys
import traceback

def generate_random_private_ip():
    block = random.choice([1, 2, 3])
    if block == 1: # 10.0.0.0/8
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    elif block == 2: # 172.16.0.0/12
        return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    else: # 192.168.0.0/16
        return f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"

def send_spoofed_L2_packets(target_ip, target_port, data_batch, spoofed_ip, iface):
    if not spoofed_ip:
        spoofed_ip = generate_random_private_ip()
    
    packet_payloads = data_batch.split('##PKT##')
    
    print(f"Received a batch of {len(packet_payloads)} packets. Sending to {target_ip}:{target_port} via {iface}...")


    for payload in packet_payloads:
        if not payload: 
            continue

        ether_layer = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")
        ip_layer = IP(src=spoofed_ip, dst=target_ip)
        udp_layer = UDP(sport=RandShort(), dport=target_port)
        raw_layer = Raw(load=payload.encode('utf-8'))
        
        packet = ether_layer / ip_layer / udp_layer / raw_layer
        sendp(packet, iface=iface, verbose=0)
    
    print("Batch sent successfully.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UDP/IP/MAC Spoofer using Scapy (Batch-enabled)")
    
    parser.add_argument("--target-ip", required=True, help="Hedef IP adresi")
    parser.add_argument("--target-port", required=True, type=int, help="Hedef port")
    parser.add_argument("--data", required=True, help="Gönderilecek veri veya '##PKT##' ile ayrılmış veri grubu")
    parser.add_argument("--spoof-ip", required=False, help="Kullanılacak sahte kaynak IP. Belirtilmezse rastgele üretilir.")
    parser.add_argument("--iface", required=True, help="Paketin gönderileceği ağ arayüzü")

    args = parser.parse_args()
    
    try:
        send_spoofed_L2_packets(args.target_ip, args.target_port, args.data, args.spoof_ip, args.iface)
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)