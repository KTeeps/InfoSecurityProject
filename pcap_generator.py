#!/usr/bin/env python3
"""
Generate synthetic PCAP files for testing anomaly detection
Requires: scapy
Install: pip install scapy
"""

from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap
import random
import time

def generate_normal_traffic(count=100, start_time=None):
    """Generate normal-sized packets (40-1500 bytes) with realistic timing"""
    packets = []
    
    if start_time is None:
        start_time = time.time()
    
    current_time = start_time
    
    # Multiple source/destination pairs for realism
    hosts = [
        ("192.168.1.10", "8.8.8.8"),
        ("192.168.1.15", "1.1.1.1"),
        ("192.168.1.20", "192.168.1.100"),
        ("192.168.1.25", "8.8.4.4"),
    ]
    
    for i in range(count):
        src_ip, dst_ip = random.choice(hosts)
        
        # Random normal packet sizes
        payload_size = random.randint(0, 1460)
        # More realistic payload (mix of bytes)
        payload = bytes([random.randint(0, 255) for _ in range(payload_size)])
        
        # Mix of protocols
        proto = random.choice(['tcp', 'udp', 'icmp'])
        
        if proto == 'tcp':
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(
                sport=random.randint(1024, 65535), 
                dport=random.choice([80, 443, 8080])
            )/payload
        elif proto == 'udp':
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(
                sport=random.randint(1024, 65535), 
                dport=random.choice([53, 123, 161])
            )/payload
        else:
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/ICMP()/payload
        
        # Set timestamp - packets arrive with realistic intervals
        # Normal traffic: 0.001 to 0.1 seconds between packets
        pkt.time = current_time
        current_time += random.uniform(0.001, 0.1)
        
        packets.append(pkt)
    
    return packets

def generate_anomalous_traffic(count=10, start_time=None):
    """Generate anomalous packets (very small or very large) with timing"""
    packets = []
    
    if start_time is None:
        start_time = time.time()
    
    current_time = start_time
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
        
        payload = bytes([random.randint(0, 255) for _ in range(payload_size)])
        pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(
            sport=random.randint(1024, 65535), 
            dport=80
        )/payload
        
        pkt.time = current_time
        current_time += random.uniform(0.001, 0.1)
        
        packets.append(pkt)
    
    return packets

def generate_exfiltration_pattern(start_time=None):
    """Simulate data exfiltration with unusual packet sizes and timing"""
    packets = []
    
    if start_time is None:
        start_time = time.time()
    
    current_time = start_time
    src_ip = "192.168.1.50"
    dst_ip = "203.0.113.10"  # Suspicious external IP
    
    # Many large outbound packets (potential data exfiltration)
    # Faster rate than normal - suspicious pattern
    for i in range(20):
        payload_size = random.randint(3000, 9000)
        payload = bytes([random.randint(0, 255) for _ in range(payload_size)])
        pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(
            sport=random.randint(1024, 65535), 
            dport=443
        )/payload
        
        # Exfiltration: rapid succession of large packets
        pkt.time = current_time
        current_time += random.uniform(0.001, 0.02)  # Faster than normal
        
        packets.append(pkt)
    
    return packets

def generate_ddos_pattern(start_time=None):
    """Simulate DDoS with many small packets in rapid succession"""
    packets = []
    
    if start_time is None:
        start_time = time.time()
    
    current_time = start_time
    dst_ip = "192.168.1.100"  # Target server
    
    # Many small packets from different sources
    for i in range(50):
        src_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
        payload_size = random.randint(0, 64)  # Small SYN flood packets
        payload = bytes([random.randint(0, 255) for _ in range(payload_size)])
        
        pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(
            sport=random.randint(1024, 65535), 
            dport=80, 
            flags="S"
        )/payload
        
        # DDoS: very rapid packet arrival
        pkt.time = current_time
        current_time += random.uniform(0.0001, 0.005)  # Very fast
        
        packets.append(pkt)
    
    return packets

def generate_tcp_connection(src_ip, dst_ip, src_port, dst_port, start_time):
    """Generate a realistic TCP connection with handshake"""
    packets = []
    current_time = start_time
    
    # SYN
    syn = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S", seq=1000)
    syn.time = current_time
    packets.append(syn)
    current_time += random.uniform(0.01, 0.05)
    
    # SYN-ACK
    synack = Ether()/IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="SA", seq=2000, ack=1001)
    synack.time = current_time
    packets.append(synack)
    current_time += random.uniform(0.01, 0.05)
    
    # ACK
    ack = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="A", seq=1001, ack=2001)
    ack.time = current_time
    packets.append(ack)
    
    return packets

def main():
    print("[+] Generating synthetic PCAP files with realistic timing...")
    
    base_time = time.time()
    
    # 1. Normal traffic PCAP
    print("[*] Creating normal_traffic.pcap")
    normal_packets = generate_normal_traffic(200, start_time=base_time)
    wrpcap("normal_traffic.pcap", normal_packets)
    print(f"    Generated {len(normal_packets)} normal packets")
    print(f"    Duration: {normal_packets[-1].time - normal_packets[0].time:.2f} seconds")
    
    # 2. Mixed traffic with anomalies
    print("[*] Creating mixed_anomalies.pcap")
    mixed_packets = (generate_normal_traffic(150, start_time=base_time) + 
                     generate_anomalous_traffic(15, start_time=base_time + 5))
    # Sort by time instead of random shuffle to maintain temporal order
    mixed_packets.sort(key=lambda x: x.time)
    wrpcap("mixed_anomalies.pcap", mixed_packets)
    print(f"    Generated {len(mixed_packets)} packets (15 anomalies)")
    print(f"    Duration: {mixed_packets[-1].time - mixed_packets[0].time:.2f} seconds")
    
    # 3. Exfiltration pattern
    print("[*] Creating exfiltration.pcap")
    exfil_packets = (generate_normal_traffic(50, start_time=base_time) + 
                     generate_exfiltration_pattern(start_time=base_time + 3))
    exfil_packets.sort(key=lambda x: x.time)
    wrpcap("exfiltration.pcap", exfil_packets)
    print(f"    Generated {len(exfil_packets)} packets (exfiltration pattern)")
    print(f"    Duration: {exfil_packets[-1].time - exfil_packets[0].time:.2f} seconds")
    
    # 4. DDoS pattern
    print("[*] Creating ddos.pcap")
    ddos_packets = (generate_normal_traffic(30, start_time=base_time) + 
                    generate_ddos_pattern(start_time=base_time + 2))
    ddos_packets.sort(key=lambda x: x.time)
    wrpcap("ddos.pcap", ddos_packets)
    print(f"    Generated {len(ddos_packets)} packets (DDoS pattern)")
    print(f"    Duration: {ddos_packets[-1].time - ddos_packets[0].time:.2f} seconds")
    
    # 5. Heavy anomalies
    print("[*] Creating heavy_anomalies.pcap")
    heavy_packets = (generate_normal_traffic(100, start_time=base_time) + 
                     generate_anomalous_traffic(40, start_time=base_time + 4))
    heavy_packets.sort(key=lambda x: x.time)
    wrpcap("heavy_anomalies.pcap", heavy_packets)
    print(f"    Generated {len(heavy_packets)} packets (40 anomalies)")
    print(f"    Duration: {heavy_packets[-1].time - heavy_packets[0].time:.2f} seconds")
    
    print("\n[+] PCAP generation complete!")
    print("\n[+] Test with your anomaly detector:")
    print("    python anomaly_detector.py normal_traffic.pcap")
    print("    python anomaly_detector.py mixed_anomalies.pcap")
    print("    python anomaly_detector.py exfiltration.pcap")
    print("    python anomaly_detector.py ddos.pcap")
    print("    python anomaly_detector.py heavy_anomalies.pcap")

if __name__ == "__main__":
    main()