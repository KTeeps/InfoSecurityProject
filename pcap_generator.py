#!/usr/bin/env python3
"""
Generate synthetic PCAP files for testing anomaly detection
Requires: scapy
Install: pip install scapy
"""

from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap
import random
import sys

def generate_normal_traffic(count=100):
    """Generate normal-sized packets (40-1500 bytes)"""
    packets = []
    src_ip = "192.168.1.10"
    dst_ip = "8.8.8.8"
    
    for i in range(count):
        # Random normal packet sizes
        payload_size = random.randint(0, 1460)
        payload = b"X" * payload_size
        
        # Mix of protocols
        proto = random.choice(['tcp', 'udp', 'icmp'])
        
        if proto == 'tcp':
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=443)/payload
        elif proto == 'udp':
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(sport=random.randint(1024, 65535), dport=53)/payload
        else:
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/ICMP()/payload
        
        packets.append(pkt)
    
    return packets

def generate_anomalous_traffic(count=10):
    """Generate anomalous packets (very small or very large)"""
    packets = []
    src_ip = "192.168.1.10"
    dst_ip = "10.0.0.1"
    
    for i in range(count):
        # Create anomalies: very small or very large packets
        if random.random() < 0.5:
            # Very small packet
            payload_size = random.randint(0, 10)
        else:
            # Very large packet (fragmented)
            payload_size = random.randint(5000, 10000)
        
        payload = b"A" * payload_size
        pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=80)/payload
        packets.append(pkt)
    
    return packets

def generate_exfiltration_pattern():
    """Simulate data exfiltration with unusual packet sizes"""
    packets = []
    src_ip = "192.168.1.50"
    dst_ip = "203.0.113.10"  # Suspicious external IP
    
    # Many large outbound packets (potential data exfiltration)
    for i in range(20):
        payload_size = random.randint(3000, 9000)
        payload = b"S" * payload_size  # Simulated sensitive data
        pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=443)/payload
        packets.append(pkt)
    
    return packets

def generate_ddos_pattern():
    """Simulate DDoS with many small packets"""
    packets = []
    dst_ip = "192.168.1.100"  # Target server
    
    # Many small packets from different sources
    for i in range(50):
        src_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
        payload_size = random.randint(0, 64)  # Small SYN flood packets
        pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=80, flags="S")/b"X"*payload_size
        packets.append(pkt)
    
    return packets

def main():
    print("[+] Generating synthetic PCAP files...")
    
    # 1. Normal traffic PCAP
    print("[*] Creating normal_traffic.pcap")
    normal_packets = generate_normal_traffic(200)
    wrpcap("normal_traffic.pcap", normal_packets)
    print(f"    Generated {len(normal_packets)} normal packets")
    
    # 2. Mixed traffic with anomalies
    print("[*] Creating mixed_anomalies.pcap")
    mixed_packets = generate_normal_traffic(150) + generate_anomalous_traffic(15)
    random.shuffle(mixed_packets)
    wrpcap("mixed_anomalies.pcap", mixed_packets)
    print(f"    Generated {len(mixed_packets)} packets (15 anomalies)")
    
    # 3. Exfiltration pattern
    print("[*] Creating exfiltration.pcap")
    exfil_packets = generate_normal_traffic(50) + generate_exfiltration_pattern()
    random.shuffle(exfil_packets)
    wrpcap("exfiltration.pcap", exfil_packets)
    print(f"    Generated {len(exfil_packets)} packets (exfiltration pattern)")
    
    # 4. DDoS pattern
    print("[*] Creating ddos.pcap")
    ddos_packets = generate_normal_traffic(30) + generate_ddos_pattern()
    random.shuffle(ddos_packets)
    wrpcap("ddos.pcap", ddos_packets)
    print(f"    Generated {len(ddos_packets)} packets (DDoS pattern)")
    
    # 5. Heavy anomalies
    print("[*] Creating heavy_anomalies.pcap")
    heavy_packets = generate_normal_traffic(100) + generate_anomalous_traffic(40)
    random.shuffle(heavy_packets)
    wrpcap("heavy_anomalies.pcap", heavy_packets)
    print(f"    Generated {len(heavy_packets)} packets (40 anomalies)")
    
    print("\n[+] PCAP generation complete!")
    print("\n[+] Test with your anomaly detector:")
    print("    python anomaly_detector.py normal_traffic.pcap")
    print("    python anomaly_detector.py mixed_anomalies.pcap")
    print("    python anomaly_detector.py exfiltration.pcap")
    print("    python anomaly_detector.py ddos.pcap")
    print("    python anomaly_detector.py heavy_anomalies.pcap")

if __name__ == "__main__":
    main()