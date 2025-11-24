#!/usr/bin/env python3
"""
Enhanced synthetic PCAP generator for network anomaly detection testing
Requires: scapy
Install: pip install scapy
"""

from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, Ether, wrpcap
import random
import time
from datetime import datetime

class TrafficGenerator:
    """Enhanced traffic generator with realistic patterns"""
    
    def __init__(self, base_time=None):
        self.base_time = base_time or time.time()
        self.current_time = self.base_time
        
        # Realistic internal and external hosts
        self.internal_hosts = [
            "192.168.1.10", "192.168.1.15", "192.168.1.20", 
            "192.168.1.25", "192.168.1.30", "192.168.1.50"
        ]
        self.external_hosts = [
            "8.8.8.8", "1.1.1.1", "142.250.80.46",  # Google
            "151.101.1.140", "104.16.249.249"  # CDNs
        ]
        self.malicious_ips = [
            "185.220.101.1", "203.0.113.10", "198.51.100.50"
        ]
        
    def generate_http_traffic(self, count=50):
        """Generate realistic HTTP/HTTPS traffic"""
        packets = []
        
        for i in range(count):
            src_ip = random.choice(self.internal_hosts)
            dst_ip = random.choice(self.external_hosts)
            src_port = random.randint(49152, 65535)
            dst_port = random.choice([80, 443])
            
            # HTTP GET request simulation
            if dst_port == 80:
                http_payload = (
                    b"GET / HTTP/1.1\r\n"
                    b"Host: example.com\r\n"
                    b"User-Agent: Mozilla/5.0\r\n"
                    b"Accept: */*\r\n\r\n"
                )
                payload_size = len(http_payload) + random.randint(0, 200)
            else:
                # HTTPS - encrypted payload
                payload_size = random.randint(100, 1400)
            
            payload = bytes([random.randint(0, 255) for _ in range(payload_size)])
            
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(
                sport=src_port, dport=dst_port, flags="PA"
            )/Raw(load=payload)
            
            pkt.time = self.current_time
            self.current_time += random.uniform(0.05, 0.5)
            packets.append(pkt)
            
            # Response packet (smaller)
            resp_size = random.randint(60, 800)
            resp_payload = bytes([random.randint(0, 255) for _ in range(resp_size)])
            resp = Ether()/IP(src=dst_ip, dst=src_ip)/TCP(
                sport=dst_port, dport=src_port, flags="PA"
            )/Raw(load=resp_payload)
            resp.time = self.current_time
            self.current_time += random.uniform(0.001, 0.05)
            packets.append(resp)
        
        return packets
    
    def generate_dns_traffic(self, count=30):
        """Generate DNS queries and responses"""
        packets = []
        domains = [
            b"google.com", b"facebook.com", b"amazon.com",
            b"cloudflare.com", b"github.com"
        ]
        
        for i in range(count):
            src_ip = random.choice(self.internal_hosts)
            dst_ip = "8.8.8.8"
            src_port = random.randint(49152, 65535)
            
            # DNS Query
            query = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(
                sport=src_port, dport=53
            )/DNS(rd=1, qd=DNSQR(qname=random.choice(domains)))
            
            query.time = self.current_time
            packets.append(query)
            self.current_time += random.uniform(0.001, 0.01)
            
            # DNS Response
            response = Ether()/IP(src=dst_ip, dst=src_ip)/UDP(
                sport=53, dport=src_port
            )/DNS(qr=1, qd=DNSQR(qname=random.choice(domains)))
            
            response.time = self.current_time
            self.current_time += random.uniform(0.05, 0.2)
            packets.append(response)
        
        return packets
    
    def generate_port_scan(self):
        """Generate port scanning pattern (anomaly)"""
        packets = []
        src_ip = random.choice(self.malicious_ips)
        dst_ip = random.choice(self.internal_hosts)
        src_port = random.randint(49152, 65535)
        
        # Scan common ports rapidly - expanded list
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443,
                 139, 135, 1433, 5900, 6379, 27017, 9200, 9300]
        
        for port in ports:
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(
                sport=src_port, dport=port, flags="S"
            )
            pkt.time = self.current_time
            self.current_time += random.uniform(0.05, 0.15)  # Faster scanning
            packets.append(pkt)
        
        return packets
    
    def generate_syn_flood(self, target_ip, count=100):
        """Generate SYN flood attack pattern"""
        packets = []
        
        for i in range(count):
            # Randomize source IP (spoofed)
            src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            src_port = random.randint(1024, 65535)
            
            pkt = Ether()/IP(src=src_ip, dst=target_ip)/TCP(
                sport=src_port, dport=80, flags="S", seq=random.randint(0, 4294967295)
            )
            
            pkt.time = self.current_time
            self.current_time += random.uniform(0.0001, 0.002)  # Extremely rapid
            packets.append(pkt)
        
        return packets
    
    def generate_data_exfiltration(self):
        """Simulate data exfiltration with large outbound transfers"""
        packets = []
        src_ip = random.choice(self.internal_hosts)
        dst_ip = random.choice(self.malicious_ips)
        src_port = random.randint(49152, 65535)
        dst_port = 9443  # Non-standard port to trigger unusual_port scoring
        
        # Sustained large outbound data transfer - MUCH more aggressive
        for i in range(100):  # Increased to 100
            payload_size = random.randint(6000, 9500)  # Even larger packets
            payload = bytes([random.randint(0, 255) for _ in range(payload_size)])
            
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(
                sport=src_port, dport=dst_port, flags="PA"
            )/Raw(load=payload)
            
            pkt.time = self.current_time
            self.current_time += random.uniform(0.015, 0.035)  # Faster sustained rate
            packets.append(pkt)
        
        return packets
    
    def generate_dns_tunneling(self):
        """Simulate DNS tunneling for data exfiltration"""
        packets = []
        src_ip = random.choice(self.internal_hosts)
        dst_ip = "8.8.8.8"
        
        # Unusual DNS queries with long encoded subdomains - VERY AGGRESSIVE
        for i in range(80):  # Increased from 50
            # Generate suspiciously long subdomain
            encoded_data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=50))
            domain = f"{encoded_data}.malicious-c2.com".encode()
            
            src_port = random.randint(49152, 65535)
            query = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(
                sport=src_port, dport=53
            )/DNS(rd=1, qd=DNSQR(qname=domain))
            
            query.time = self.current_time
            self.current_time += random.uniform(0.05, 0.10)  # Much faster, more consistent rate
            packets.append(query)
        
        return packets
    
    def generate_icmp_tunnel(self):
        """Simulate ICMP tunneling"""
        packets = []
        src_ip = random.choice(self.internal_hosts)
        dst_ip = random.choice(self.malicious_ips)
        
        for i in range(40):  # Increased from 25
            # ICMP with unusually large payload
            payload_size = random.randint(800, 1400)  # Larger payloads
            payload = bytes([random.randint(0, 255) for _ in range(payload_size)])
            
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/ICMP()/Raw(load=payload)
            pkt.time = self.current_time
            self.current_time += random.uniform(0.03, 0.10)  # Faster
            packets.append(pkt)
        
        return packets
    
    def generate_slowloris_attack(self, target_ip):
        """Simulate Slowloris attack (many incomplete HTTP connections)"""
        packets = []
        src_ip = random.choice(self.internal_hosts)
        
        # Many connections that send partial HTTP requests
        for i in range(40):
            src_port = random.randint(49152, 65535)
            
            # SYN
            syn = Ether()/IP(src=src_ip, dst=target_ip)/TCP(
                sport=src_port, dport=80, flags="S"
            )
            syn.time = self.current_time
            packets.append(syn)
            self.current_time += random.uniform(0.01, 0.05)
            
            # Partial HTTP request
            partial_http = b"GET / HTTP/1.1\r\nHost: target.com\r\n"
            req = Ether()/IP(src=src_ip, dst=target_ip)/TCP(
                sport=src_port, dport=80, flags="PA"
            )/Raw(load=partial_http)
            req.time = self.current_time
            packets.append(req)
            self.current_time += random.uniform(0.5, 2.0)  # Slow
        
        return packets
    
    def generate_fragmentation_attack(self, target_ip):
        """Generate IP fragmentation attack"""
        packets = []
        src_ip = random.choice(self.malicious_ips)
        
        for i in range(30):
            # Create many small fragments
            for frag_id in range(5):
                payload = bytes([random.randint(0, 255) for _ in range(200)])
                pkt = Ether()/IP(
                    src=src_ip, dst=target_ip, 
                    flags="MF", frag=frag_id * 25
                )/UDP(sport=random.randint(1024, 65535), dport=53)/Raw(load=payload)
                
                pkt.time = self.current_time
                self.current_time += random.uniform(0.0001, 0.001)
                packets.append(pkt)
        
        return packets
    
    def generate_normal_background(self, count=100):
        """Generate realistic background traffic"""
        packets = []
        packets.extend(self.generate_http_traffic(count // 2))
        packets.extend(self.generate_dns_traffic(count // 3))
        
        # Add some ICMP ping
        for i in range(count // 10):
            src_ip = random.choice(self.internal_hosts)
            dst_ip = random.choice(self.external_hosts)
            
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/ICMP()
            pkt.time = self.current_time
            self.current_time += random.uniform(0.5, 2.0)
            packets.append(pkt)
        
        return packets


def main():
    print("[+] Enhanced PCAP Generator for Anomaly Detection")
    print("[+] Generating synthetic network traffic...\n")
    
    base_time = time.time()
    
    # 1. Clean normal traffic
    print("[*] Creating 1_normal_traffic.pcap")
    gen = TrafficGenerator(base_time)
    normal = gen.generate_normal_background(150)
    normal.sort(key=lambda x: x.time)
    wrpcap("1_normal_traffic.pcap", normal)
    print(f"    ✓ {len(normal)} packets | Duration: {normal[-1].time - normal[0].time:.2f}s")
    
    # 2. Port scan attack
    print("[*] Creating 2_port_scan.pcap")
    gen = TrafficGenerator(base_time)
    port_scan = gen.generate_normal_background(80)
    port_scan.extend(gen.generate_port_scan())
    port_scan.extend(gen.generate_port_scan())
    port_scan.sort(key=lambda x: x.time)
    wrpcap("2_port_scan.pcap", port_scan)
    print(f"    ✓ {len(port_scan)} packets | Duration: {port_scan[-1].time - port_scan[0].time:.2f}s")
    
    # 3. SYN flood DDoS
    print("[*] Creating 3_syn_flood.pcap")
    gen = TrafficGenerator(base_time)
    syn_flood = gen.generate_normal_background(50)
    syn_flood.extend(gen.generate_syn_flood("192.168.1.100", 150))
    syn_flood.sort(key=lambda x: x.time)
    wrpcap("3_syn_flood.pcap", syn_flood)
    print(f"    ✓ {len(syn_flood)} packets | Duration: {syn_flood[-1].time - syn_flood[0].time:.2f}s")
    
    # 4. Data exfiltration
    print("[*] Creating 4_exfiltration.pcap")
    gen = TrafficGenerator(base_time)
    exfil = gen.generate_normal_background(70)
    exfil.extend(gen.generate_data_exfiltration())
    exfil.sort(key=lambda x: x.time)
    wrpcap("4_exfiltration.pcap", exfil)
    print(f"    ✓ {len(exfil)} packets | Duration: {exfil[-1].time - exfil[0].time:.2f}s")
    
    # 5. DNS tunneling
    print("[*] Creating 5_dns_tunneling.pcap")
    gen = TrafficGenerator(base_time)
    dns_tunnel = gen.generate_normal_background(60)
    dns_tunnel.extend(gen.generate_dns_tunneling())
    dns_tunnel.sort(key=lambda x: x.time)
    wrpcap("5_dns_tunneling.pcap", dns_tunnel)
    print(f"    ✓ {len(dns_tunnel)} packets | Duration: {dns_tunnel[-1].time - dns_tunnel[0].time:.2f}s")
    
    # 6. ICMP tunneling
    print("[*] Creating 6_icmp_tunnel.pcap")
    gen = TrafficGenerator(base_time)
    icmp_tunnel = gen.generate_normal_background(60)
    icmp_tunnel.extend(gen.generate_icmp_tunnel())
    icmp_tunnel.sort(key=lambda x: x.time)
    wrpcap("6_icmp_tunnel.pcap", icmp_tunnel)
    print(f"    ✓ {len(icmp_tunnel)} packets | Duration: {icmp_tunnel[-1].time - icmp_tunnel[0].time:.2f}s")
    
    # 7. Slowloris attack
    print("[*] Creating 7_slowloris.pcap")
    gen = TrafficGenerator(base_time)
    slowloris = gen.generate_normal_background(50)
    slowloris.extend(gen.generate_slowloris_attack("192.168.1.100"))
    slowloris.sort(key=lambda x: x.time)
    wrpcap("7_slowloris.pcap", slowloris)
    print(f"    ✓ {len(slowloris)} packets | Duration: {slowloris[-1].time - slowloris[0].time:.2f}s")
    
    # 8. Fragmentation attack
    print("[*] Creating 8_fragmentation.pcap")
    gen = TrafficGenerator(base_time)
    frag_attack = gen.generate_normal_background(50)
    frag_attack.extend(gen.generate_fragmentation_attack("192.168.1.100"))
    frag_attack.sort(key=lambda x: x.time)
    wrpcap("8_fragmentation.pcap", frag_attack)
    print(f"    ✓ {len(frag_attack)} packets | Duration: {frag_attack[-1].time - frag_attack[0].time:.2f}s")
    
    # 9. Mixed attacks
    print("[*] Creating 9_mixed_attacks.pcap")
    gen = TrafficGenerator(base_time)
    mixed = gen.generate_normal_background(80)
    mixed.extend(gen.generate_port_scan())
    mixed.extend(gen.generate_port_scan())  # Two port scans
    mixed.extend(gen.generate_data_exfiltration())
    mixed.extend(gen.generate_dns_tunneling())
    mixed.extend(gen.generate_icmp_tunnel())
    mixed.sort(key=lambda x: x.time)
    wrpcap("9_mixed_attacks.pcap", mixed)
    print(f"    ✓ {len(mixed)} packets | Duration: {mixed[-1].time - mixed[0].time:.2f}s")
    
    print("\n[+] PCAP generation complete!")
    print("\n[📊] Generated attack scenarios:")
    print("    1. Normal traffic (baseline)")
    print("    2. Port scan attack")
    print("    3. SYN flood DDoS")
    print("    4. Data exfiltration")
    print("    5. DNS tunneling")
    print("    6. ICMP tunneling")
    print("    7. Slowloris attack")
    print("    8. Fragmentation attack")
    print("    9. Mixed attacks")
    print("\n[🔍] Test with: python anomaly_detector.py <pcap_file>")

if __name__ == "__main__":
    main()