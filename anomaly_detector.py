#!/usr/bin/env python3
"""
Improved Network Anomaly Detector with reduced false positives
Uses context-aware detection, adaptive thresholds, and behavioral baselines
"""

import dpkt
import socket
import numpy as np
import json
from collections import defaultdict, Counter
from datetime import datetime
import sys

class FlowKey:
    """Represents a unique network flow (5-tuple)"""
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
    
    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto))
    
    def __eq__(self, other):
        return (self.src_ip == other.src_ip and self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and self.dst_port == other.dst_port and
                self.proto == other.proto)
    
    def __repr__(self):
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({self.proto})"

class Flow:
    """Stores information about a network flow"""
    def __init__(self, key):
        self.key = key
        self.packets = []
        self.sizes = []
        self.timestamps = []
        self.tcp_flags = []
        self.total_bytes = 0
        self.start_time = None
        self.end_time = None
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
    
    def add_packet(self, ts, size, flags=None):
        if self.start_time is None:
            self.start_time = ts
        self.end_time = ts
        self.packets.append((ts, size, flags))
        self.sizes.append(size)
        self.timestamps.append(ts)
        self.tcp_flags.append(flags)
        self.total_bytes += size
        
        # Count TCP flags
        if flags is not None:
            if flags & dpkt.tcp.TH_SYN:
                self.syn_count += 1
            if flags & dpkt.tcp.TH_ACK:
                self.ack_count += 1
            if flags & dpkt.tcp.TH_FIN:
                self.fin_count += 1
            if flags & dpkt.tcp.TH_RST:
                self.rst_count += 1
    
    def get_duration(self):
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0
    
    def get_packet_rate(self):
        duration = self.get_duration()
        return len(self.packets) / duration if duration > 0 else 0
    
    def get_byte_rate(self):
        duration = self.get_duration()
        return self.total_bytes / duration if duration > 0 else 0
    
    def get_inter_arrival_times(self):
        if len(self.timestamps) < 2:
            return []
        return [self.timestamps[i+1] - self.timestamps[i] for i in range(len(self.timestamps)-1)]
    
    def is_established_connection(self):
        """Check if TCP connection was properly established"""
        return self.syn_count > 0 and self.ack_count > 0

def is_private_ip(ip):
    """Check if IP is in private address space"""
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.16.") or ip.startswith("172.17.") or
        ip.startswith("172.18.") or ip.startswith("172.19.") or
        ip.startswith("172.20.") or ip.startswith("172.21.") or
        ip.startswith("172.22.") or ip.startswith("172.23.") or
        ip.startswith("172.24.") or ip.startswith("172.25.") or
        ip.startswith("172.26.") or ip.startswith("172.27.") or
        ip.startswith("172.28.") or ip.startswith("172.29.") or
        ip.startswith("172.30.") or ip.startswith("172.31.")
    )

def is_known_service(dst_ip, dst_port):
    """Enhanced check for legitimate services"""
    # Well-known public services
    known_services = {
        # DNS servers
        "8.8.8.8", "8.8.4.4",  # Google
        "1.1.1.1", "1.0.0.1",  # Cloudflare
        "9.9.9.9", "149.112.112.112",  # Quad9
        # Popular CDNs (partial list)
        "151.101.1.140", "151.101.65.140",  # Fastly
        "104.16.0.0", "104.17.0.0",  # Cloudflare ranges
    }
    
    # Common CDN/cloud ranges
    cdn_ranges = [
        "8.8.", "8.34.",  # Google
        "1.1.", "1.0.",   # Cloudflare
        "104.16.", "104.17.", "104.18.",  # Cloudflare
        "151.101.",  # Fastly
        "13.32.", "13.35.",  # AWS CloudFront
        "23.32.", "23.44.",  # Akamai
    ]
    
    # Check exact match
    if dst_ip in known_services:
        return True
    
    # Check range match
    for prefix in cdn_ranges:
        if dst_ip.startswith(prefix):
            return True
    
    # Check for standard service ports
    standard_ports = {53, 80, 443, 853}  # DNS, HTTP, HTTPS, DNS-over-TLS
    if dst_port in standard_ports:
        return True
    
    return False

def parse_pcap(path, whitelist_ips=None):
    """Parse PCAP with detailed protocol analysis"""
    flows = defaultdict(Flow)
    packets = []
    errors = 0
    
    if whitelist_ips is None:
        whitelist_ips = set()
    
    with open(path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                
                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                proto = ip.p
                size = len(buf)
                
                # Skip whitelisted IPs
                if src_ip in whitelist_ips or dst_ip in whitelist_ips:
                    continue
                
                # Extract transport layer info
                src_port = 0
                dst_port = 0
                tcp_flags = None
                proto_name = "OTHER"
                
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    tcp_flags = tcp.flags
                    proto_name = "TCP"
                    
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    src_port = udp.sport
                    dst_port = udp.dport
                    proto_name = "UDP"
                    
                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    proto_name = "ICMP"
                
                # Create flow key
                flow_key = FlowKey(src_ip, dst_ip, src_port, dst_port, proto_name)
                
                # Add to flow
                if flow_key not in flows:
                    flows[flow_key] = Flow(flow_key)
                flows[flow_key].add_packet(ts, size, tcp_flags)
                
                # Store individual packet
                packets.append({
                    'timestamp': ts,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'proto': proto_name,
                    'size': size,
                    'tcp_flags': tcp_flags
                })
                
            except Exception as e:
                errors += 1
                continue
    
    return packets, flows, errors

def calculate_baseline(flows):
    """Calculate baseline statistics for normal behavior"""
    all_sizes = []
    all_rates = []
    all_durations = []
    
    for flow in flows.values():
        all_sizes.extend(flow.sizes)
        if flow.get_duration() > 0:
            all_rates.append(flow.get_byte_rate())
            all_durations.append(flow.get_duration())
    
    baseline = {
        'size_mean': np.mean(all_sizes) if all_sizes else 0,
        'size_std': np.std(all_sizes) if all_sizes else 0,
        'size_p95': np.percentile(all_sizes, 95) if all_sizes else 0,
        'rate_mean': np.mean(all_rates) if all_rates else 0,
        'rate_std': np.std(all_rates) if all_rates else 0,
        'rate_p95': np.percentile(all_rates, 95) if all_rates else 0,
    }
    
    return baseline

def detect_size_anomalies(sizes, threshold=3.5):
    """
    Improved size anomaly detection with higher threshold
    Uses MAD (Median Absolute Deviation) for robustness
    """
    if len(sizes) < 10:  # Need more samples
        return [], 0, 0
    
    median = np.median(sizes)
    mad = np.median([abs(s - median) for s in sizes])
    
    # Modified z-score using MAD
    if mad == 0:
        return [], median, 0
    
    anomalies = []
    for i, s in enumerate(sizes):
        modified_z = 0.6745 * (s - median) / mad
        if abs(modified_z) > threshold:
            anomalies.append((i, s, modified_z))
    
    return anomalies, median, mad

def detect_port_scanning(flows, threshold=12, time_window=10.0):
    """
    Improved port scan detection - more realistic threshold
    """
    src_scan_data = defaultdict(lambda: {'ports': set(), 'timestamps': []})
    
    for flow_key, flow in flows.items():
        if flow.key.proto != "TCP":
            continue
        
        # Count SYN attempts (whether or not connection established)
        if flow.syn_count > 0:
            src = flow.key.src_ip
            dst_port = flow.key.dst_port
            src_scan_data[src]['ports'].add(dst_port)
            src_scan_data[src]['timestamps'].append(flow.start_time)
    
    scanners = []
    for src, data in src_scan_data.items():
        port_count = len(data['ports'])
        
        # Lower threshold
        if port_count < threshold:
            continue
        
        # Calculate scan rate
        if len(data['timestamps']) > 1:
            timestamps = sorted(data['timestamps'])
            duration = timestamps[-1] - timestamps[0]
            scan_rate = port_count / duration if duration > 0 else 0
            
            # More lenient rate check
            if scan_rate > 0.5:  # Was 1.0 - more than 0.5 ports per second
                scanners.append({
                    'src_ip': src,
                    'port_count': port_count,
                    'duration': duration,
                    'scan_rate': scan_rate
                })
    
    return scanners

def detect_syn_flood(flows, syn_threshold=50):
    """
    Improved SYN flood detection
    Focuses on destination-based analysis
    """
    dst_syn_data = defaultdict(lambda: {'syn_count': 0, 'sources': set(), 'rate': 0})
    
    for flow_key, flow in flows.items():
        if flow.key.proto != "TCP":
            continue
        
        # Count SYNs without established connections
        if flow.syn_count > 0 and not flow.is_established_connection():
            dst = flow.key.dst_ip
            dst_syn_data[dst]['syn_count'] += flow.syn_count
            dst_syn_data[dst]['sources'].add(flow.key.src_ip)
            
            duration = flow.get_duration()
            if duration > 0:
                dst_syn_data[dst]['rate'] += flow.syn_count / duration
    
    syn_floods = []
    for dst, data in dst_syn_data.items():
        # High number of SYNs from multiple sources
        if data['syn_count'] > syn_threshold and len(data['sources']) > 10:
            syn_floods.append({
                'target': dst,
                'syn_count': data['syn_count'],
                'unique_sources': len(data['sources']),
                'avg_rate': data['rate'] / len(data['sources'])
            })
    
    return syn_floods

def detect_data_exfiltration(flows, internal_ips, baseline):
    """
    Improved exfiltration detection with adjusted thresholds
    """
    exfil_candidates = []
    
    # Much more aggressive thresholds
    size_threshold = max(baseline.get('size_p95', 1500) * 1.5, 150000)  # 150KB minimum
    rate_threshold = max(baseline.get('rate_p95', 50000) * 1.2, 30000)  # 30KB/s minimum
    
    for flow_key, flow in flows.items():
        # Skip non-TCP/UDP
        if flow.key.proto not in ["TCP", "UDP"]:
            continue
        
        # Only outbound from internal network
        if flow.key.src_ip not in internal_ips or flow.key.dst_ip in internal_ips:
            continue
        
        # Skip known legitimate services
        if is_known_service(flow.key.dst_ip, flow.key.dst_port):
            continue
        
        # Very low minimum packet count
        if len(flow.packets) < 10:
            continue
        
        duration = flow.get_duration()
        if duration < 0.2:
            continue
        
        # Scoring system
        score = 0
        reasons = []
        
        # 1. Large total transfer
        if flow.total_bytes > size_threshold:
            score += 4
            reasons.append(f"large_volume_{flow.total_bytes/1024/1024:.2f}MB")
        elif flow.total_bytes > 100000:  # Even lower medium threshold
            score += 3
            reasons.append(f"medium_volume_{flow.total_bytes/1024/1024:.2f}MB")
        
        # 2. High sustained rate
        byte_rate = flow.get_byte_rate()
        if byte_rate > rate_threshold:
            score += 4
            reasons.append(f"high_rate_{byte_rate/1024:.1f}KB/s")
        elif byte_rate > 20000:  # Lower medium rate
            score += 2
            reasons.append(f"medium_rate_{byte_rate/1024:.1f}KB/s")
        
        # 3. Sustained activity
        packet_rate = flow.get_packet_rate()
        if duration > 10 and packet_rate > 0.3:
            score += 2
            reasons.append(f"sustained_{duration:.0f}s_{packet_rate:.1f}pps")
        
        # 4. Unusual destination port - more aggressive
        common_ports = {80, 443, 53, 22, 25, 587, 993, 995, 8080, 8443}
        if flow.key.dst_port not in common_ports and flow.total_bytes > 100000:
            score += 3  # Increased from 2
            reasons.append(f"unusual_port_{flow.key.dst_port}")
        
        # 5. Large average packet size
        avg_packet_size = np.mean(flow.sizes)
        if avg_packet_size > 600:  # Lowered from 700
            score += 2
            reasons.append(f"large_packets_{avg_packet_size:.0f}B")
        
        # 6. Many large packets
        large_packets = sum(1 for s in flow.sizes if s > 2500)  # Lowered from 3000
        if large_packets > 8:  # Lowered from 10
            score += 2
            reasons.append(f"{large_packets}_jumbo_packets")
        
        # Very lenient threshold
        if score >= 4:  # Lowered from 5
            exfil_candidates.append({
                'flow': str(flow_key),
                'total_bytes': flow.total_bytes,
                'byte_rate': byte_rate,
                'duration': duration,
                'packets': len(flow.packets),
                'avg_packet_size': avg_packet_size,
                'score': score,
                'reasons': reasons,
                'confidence': 'HIGH' if score >= 8 else 'MEDIUM'
            })
    
    return exfil_candidates


def detect_beaconing(flows, min_packets=10, cv_threshold=0.25):
    """
    Improved beaconing detection with more realistic parameters
    """
    beacons = []
    
    for flow_key, flow in flows.items():
        # Need enough samples
        if len(flow.packets) < min_packets:
            continue
        
        inter_arrival = flow.get_inter_arrival_times()
        if len(inter_arrival) < min_packets - 1:
            continue
        
        # Filter out very short intervals (noise)
        inter_arrival = [t for t in inter_arrival if t > 0.05]  # Was 0.1
        if len(inter_arrival) < min_packets - 1:
            continue
        
        mean_iat = np.mean(inter_arrival)
        std_iat = np.std(inter_arrival)
        
        # More lenient minimum interval
        if mean_iat < 0.5:  # Was 1.0
            continue
        
        if mean_iat > 0:
            cv = std_iat / mean_iat
            
            # More lenient regularity threshold
            if cv < cv_threshold:
                duration = flow.get_duration()
                if duration > 30:  # Was 60 - at least 30 seconds
                    beacons.append({
                        'flow': str(flow_key),
                        'packets': len(flow.packets),
                        'mean_interval': mean_iat,
                        'regularity_score': 1 - cv,
                        'duration': duration,
                        'confidence': 'HIGH' if cv < 0.15 else 'MEDIUM'
                    })
    
    return beacons


def detect_dns_tunneling(flows):
    """
    Improved DNS tunneling detection - very aggressive
    """
    dns_anomalies = []
    
    for flow_key, flow in flows.items():
        # Focus on DNS traffic
        if flow.key.dst_port != 53 or flow.key.proto != "UDP":
            continue
        
        # Check for high query volume
        duration = flow.get_duration()
        if duration > 0:
            query_rate = len(flow.packets) / duration
            
            # Much lower thresholds for detection
            if query_rate > 2 and len(flow.packets) > 20:  # Was 3 qps and 25 packets
                dns_anomalies.append({
                    'flow': str(flow_key),
                    'query_rate': query_rate,
                    'total_queries': len(flow.packets),
                    'duration': duration,
                    'type': 'high_volume',
                    'confidence': 'HIGH' if query_rate > 5 else 'MEDIUM'
                })
        elif len(flow.packets) > 30:  # Fallback: just high packet count
            dns_anomalies.append({
                'flow': str(flow_key),
                'query_rate': 0,
                'total_queries': len(flow.packets),
                'duration': 0,
                'type': 'high_volume',
                'confidence': 'MEDIUM'
            })
    
    return dns_anomalies

def detect_icmp_tunneling(flows):
    """
    Detect ICMP tunneling - large or frequent ICMP traffic
    """
    icmp_anomalies = []
    
    for flow_key, flow in flows.items():
        if flow.key.proto != "ICMP":
            continue
        
        # Skip if too few packets
        if len(flow.packets) < 15:
            continue
        
        avg_size = np.mean(flow.sizes)
        duration = flow.get_duration()
        
        score = 0
        reasons = []
        
        # Large ICMP packets (normal ping is ~64 bytes)
        if avg_size > 500:
            score += 3
            reasons.append(f"large_icmp_{avg_size:.0f}B")
        
        # High volume
        if flow.total_bytes > 50000:
            score += 2
            reasons.append(f"high_volume_{flow.total_bytes/1024:.1f}KB")
        
        # High rate
        if duration > 0:
            packet_rate = len(flow.packets) / duration
            if packet_rate > 5:
                score += 2
                reasons.append(f"high_rate_{packet_rate:.1f}pps")
        
        # Many packets
        if len(flow.packets) > 20:
            score += 1
            reasons.append(f"{len(flow.packets)}_packets")
        
        if score >= 4:
            icmp_anomalies.append({
                'flow': str(flow_key),
                'packets': len(flow.packets),
                'avg_size': avg_size,
                'total_bytes': flow.total_bytes,
                'duration': duration,
                'score': score,
                'reasons': reasons,
                'confidence': 'HIGH' if score >= 6 else 'MEDIUM'
            })
    
    return icmp_anomalies

def detect_slowloris(flows):
    """
    Detect Slowloris attacks - many incomplete HTTP connections
    """
    slowloris_targets = defaultdict(lambda: {'incomplete': 0, 'sources': set(), 'total': 0})
    
    for flow_key, flow in flows.items():
        # Focus on HTTP/HTTPS traffic
        if flow.key.dst_port not in [80, 443, 8080]:
            continue
        
        if flow.key.proto != "TCP":
            continue
        
        dst = flow.key.dst_ip
        slowloris_targets[dst]['total'] += 1
        
        # Check for incomplete connections
        # SYN sent but connection never properly established
        if flow.syn_count > 0 and flow.fin_count == 0 and flow.rst_count == 0:
            slowloris_targets[dst]['incomplete'] += 1
            slowloris_targets[dst]['sources'].add(flow.key.src_ip)
    
    slowloris_attacks = []
    for target, data in slowloris_targets.items():
        # High ratio of incomplete connections
        if data['total'] > 20 and data['incomplete'] > 15:
            ratio = data['incomplete'] / data['total']
            if ratio > 0.6:  # More than 60% incomplete
                slowloris_attacks.append({
                    'target': target,
                    'incomplete_connections': data['incomplete'],
                    'total_connections': data['total'],
                    'incomplete_ratio': ratio,
                    'unique_sources': len(data['sources']),
                    'confidence': 'HIGH' if ratio > 0.8 else 'MEDIUM'
                })
    
    return slowloris_attacks

def detect_fragmentation_attack(flows):
    """
    Detect IP fragmentation attacks
    """
    frag_data = defaultdict(lambda: {'fragments': 0, 'sources': set()})
    
    for flow_key, flow in flows.items():
        # Look for many small packets that could be fragments
        if len(flow.packets) < 10:
            continue
        
        # Check for unusual patterns - many very small packets
        small_packets = sum(1 for s in flow.sizes if s < 300)
        if small_packets > len(flow.packets) * 0.7:  # >70% are small
            dst = flow.key.dst_ip
            frag_data[dst]['fragments'] += len(flow.packets)
            frag_data[dst]['sources'].add(flow.key.src_ip)
    
    frag_attacks = []
    for target, data in frag_data.items():
        if data['fragments'] > 50:  # Many fragments
            frag_attacks.append({
                'target': target,
                'fragment_count': data['fragments'],
                'unique_sources': len(data['sources']),
                'confidence': 'MEDIUM'
            })
    
    return frag_attacks

def detect_protocol_anomalies(flows):
    """
    Detect protocol mismatches (less strict)
    """
    anomalies = []
    
    # Expected protocols for well-known ports
    expected = {
        80: 'TCP', 443: 'TCP', 22: 'TCP', 21: 'TCP', 25: 'TCP',
        53: 'UDP', 123: 'UDP', 161: 'UDP', 514: 'UDP'
    }
    
    for flow_key, flow in flows.items():
        dst_port = flow.key.dst_port
        proto = flow.key.proto
        
        if dst_port in expected and proto != expected[dst_port]:
            # Only report if there's significant traffic
            if len(flow.packets) > 10:
                anomalies.append({
                    'flow': str(flow_key),
                    'expected_proto': expected[dst_port],
                    'actual_proto': proto,
                    'packets': len(flow.packets)
                })
    
    return anomalies

def analyze_traffic_statistics(packets, flows):
    """Generate comprehensive traffic statistics"""
    if not packets:
        return {}
    
    proto_counts = Counter([p['proto'] for p in packets])
    total_packets = len(packets)
    
    sizes = [p['size'] for p in packets]
    timestamps = [p['timestamp'] for p in packets]
    
    duration = max(timestamps) - min(timestamps) if timestamps else 0
    
    src_counts = Counter([p['src_ip'] for p in packets])
    dst_counts = Counter([p['dst_ip'] for p in packets])
    dst_ports = [p['dst_port'] for p in packets if p['dst_port'] > 0]
    port_counts = Counter(dst_ports)
    
    # Flow statistics
    flow_durations = [f.get_duration() for f in flows.values() if f.get_duration() > 0]
    flow_sizes = [f.total_bytes for f in flows.values()]
    
    stats = {
        'total_packets': total_packets,
        'total_flows': len(flows),
        'duration': duration,
        'packets_per_second': total_packets / duration if duration > 0 else 0,
        'protocol_distribution': dict(proto_counts),
        'avg_packet_size': np.mean(sizes),
        'median_packet_size': np.median(sizes),
        'p95_packet_size': np.percentile(sizes, 95),
        'avg_flow_duration': np.mean(flow_durations) if flow_durations else 0,
        'avg_flow_size': np.mean(flow_sizes) if flow_sizes else 0,
        'top_sources': src_counts.most_common(5),
        'top_destinations': dst_counts.most_common(5),
        'top_ports': port_counts.most_common(10)
    }
    
    return stats

def debug_flows(flows, internal_ips):
    """Print detailed flow information for debugging"""
    print("\n" + "="*80)
    print("FLOW DEBUG INFORMATION")
    print("="*80)
    
    # Analyze outbound flows
    outbound_flows = []
    for flow_key, flow in flows.items():
        if flow.key.src_ip in internal_ips and flow.key.dst_ip not in internal_ips:
            outbound_flows.append((flow_key, flow))
    
    print(f"\nTotal flows: {len(flows)}")
    print(f"Outbound flows: {len(outbound_flows)}")
    
    # Show top 10 largest outbound flows
    outbound_flows.sort(key=lambda x: x[1].total_bytes, reverse=True)
    
    print("\n📊 TOP 10 OUTBOUND FLOWS BY SIZE:")
    print("-" * 80)
    for i, (key, flow) in enumerate(outbound_flows[:10], 1):
        duration = flow.get_duration()
        rate = flow.get_byte_rate()
        avg_size = np.mean(flow.sizes) if flow.sizes else 0
        
        print(f"\n{i}. {key}")
        print(f"   Total bytes:   {flow.total_bytes:,} ({flow.total_bytes/1024/1024:.2f} MB)")
        print(f"   Packets:       {len(flow.packets)}")
        print(f"   Duration:      {duration:.2f}s")
        print(f"   Byte rate:     {rate/1024:.1f} KB/s")
        print(f"   Avg pkt size:  {avg_size:.0f} bytes")
        print(f"   Protocol:      {key.proto}")
        print(f"   Dst port:      {key.dst_port}")
        
        # Check against thresholds
        issues = []
        if flow.total_bytes < 150000:
            issues.append(f"❌ Too small (need 150KB, have {flow.total_bytes/1024:.0f}KB)")
        if len(flow.packets) < 10:
            issues.append(f"❌ Too few packets (need 10, have {len(flow.packets)})")
        if duration < 0.2:
            issues.append(f"❌ Too short (need 0.2s, have {duration:.2f}s)")
        if rate < 30000 and flow.total_bytes < 150000:
            issues.append(f"❌ Low rate and volume")
        
        if issues:
            print(f"   ⚠️  Issues: {'; '.join(issues)}")
        else:
            print(f"   ✅ Should be detected!")
    
    # DNS flows
    dns_flows = [(k, f) for k, f in flows.items() if k.dst_port == 53 and k.proto == "UDP"]
    print(f"\n\n📊 DNS FLOWS ({len(dns_flows)} total):")
    print("-" * 80)
    
    for key, flow in dns_flows[:5]:
        duration = flow.get_duration()
        rate = len(flow.packets) / duration if duration > 0 else 0
        
        print(f"\n{key}")
        print(f"   Packets:       {len(flow.packets)}")
        print(f"   Duration:      {duration:.2f}s")
        print(f"   Query rate:    {rate:.2f} qps")
        
        issues = []
        if len(flow.packets) < 20:
            issues.append(f"❌ Too few queries (need 20, have {len(flow.packets)})")
        if duration > 0 and rate < 2:
            issues.append(f"❌ Rate too slow (need 2 qps, have {rate:.2f})")
        
        if issues:
            print(f"   ⚠️  Issues: {'; '.join(issues)}")
        else:
            print(f"   ✅ Should be detected!")

def generate_report(packets, flows, anomalies, stats, output_format='text'):
    """Generate analysis report with severity levels"""
    report = {
        'analysis_timestamp': datetime.now().isoformat(),
        'statistics': stats,
        'anomalies': anomalies
    }
    
    if output_format == 'json':
        return json.dumps(report, indent=2, default=str)
    
    # Text format
    lines = []
    lines.append("=" * 80)
    lines.append("NETWORK ANOMALY DETECTION REPORT")
    lines.append("=" * 80)
    lines.append(f"Analysis Time: {report['analysis_timestamp']}")
    lines.append("")
    
    # Statistics
    lines.append("📊 TRAFFIC STATISTICS")
    lines.append("-" * 80)
    lines.append(f"Total Packets:       {stats['total_packets']:,}")
    lines.append(f"Total Flows:         {stats['total_flows']:,}")
    lines.append(f"Capture Duration:    {stats['duration']:.2f} seconds")
    lines.append(f"Packet Rate:         {stats['packets_per_second']:.2f} pkt/s")
    lines.append(f"Avg Packet Size:     {stats['avg_packet_size']:.0f} bytes")
    lines.append(f"95th Percentile:     {stats['p95_packet_size']:.0f} bytes")
    lines.append("")
    
    lines.append("Protocol Distribution:")
    for proto, count in sorted(stats['protocol_distribution'].items()):
        pct = (count / stats['total_packets']) * 100
        bar = "█" * int(pct / 2)
        lines.append(f"  {proto:6s}: {count:6d} ({pct:5.1f}%) {bar}")
    lines.append("")
    
    # Count total anomalies
    total_anomalies = sum([
        len(anomalies.get('port_scanning', [])),
        len(anomalies.get('syn_floods', [])),
        len(anomalies.get('data_exfiltration', [])),
        len(anomalies.get('beaconing', [])),
        len(anomalies.get('dns_tunneling', [])),
        len(anomalies.get('icmp_tunneling', [])),
        len(anomalies.get('slowloris', [])),
        len(anomalies.get('fragmentation', [])),
        len(anomalies.get('protocol_anomalies', []))
    ])
    
    if total_anomalies == 0:
        lines.append("✅ NO SIGNIFICANT ANOMALIES DETECTED")
        lines.append("")
        lines.append("Traffic appears normal. All metrics within expected ranges.")
    else:
        lines.append(f"🚨 DETECTED ANOMALIES ({total_anomalies} total)")
        lines.append("-" * 80)
        
        # Port scanning
        if anomalies.get('port_scanning'):
            lines.append(f"\n⚠️  PORT SCANNING: {len(anomalies['port_scanning'])} sources detected")
            for scan in anomalies['port_scanning'][:5]:
                lines.append(f"    └─ {scan['src_ip']}")
                lines.append(f"       Ports scanned: {scan['port_count']}, Rate: {scan['scan_rate']:.1f} ports/s")
        
        # SYN floods
        if anomalies.get('syn_floods'):
            lines.append(f"\n🔴 SYN FLOOD: {len(anomalies['syn_floods'])} targets detected")
            for flood in anomalies['syn_floods'][:5]:
                lines.append(f"    └─ Target: {flood['target']}")
                lines.append(f"       {flood['syn_count']} SYNs from {flood['unique_sources']} sources")
        
        # Data exfiltration
        if anomalies.get('data_exfiltration'):
            lines.append(f"\n🔴 POTENTIAL DATA EXFILTRATION: {len(anomalies['data_exfiltration'])} flows")
            for exfil in sorted(anomalies['data_exfiltration'], key=lambda x: x['score'], reverse=True)[:5]:
                lines.append(f"    └─ [{exfil['confidence']}] {exfil['flow']}")
                lines.append(f"       Volume: {exfil['total_bytes']/1024/1024:.2f} MB, "
                           f"Rate: {exfil['byte_rate']/1024:.1f} KB/s, "
                           f"Duration: {exfil['duration']:.0f}s")
                lines.append(f"       Indicators: {', '.join(exfil['reasons'])}")
        
        # Beaconing
        if anomalies.get('beaconing'):
            lines.append(f"\n⚠️  C2 BEACONING: {len(anomalies['beaconing'])} flows detected")
            for beacon in anomalies['beaconing'][:5]:
                lines.append(f"    └─ [{beacon['confidence']}] {beacon['flow']}")
                lines.append(f"       Interval: {beacon['mean_interval']:.2f}s, "
                           f"Regularity: {beacon['regularity_score']:.3f}")
        
        # DNS tunneling
        if anomalies.get('dns_tunneling'):
            lines.append(f"\n⚠️  DNS TUNNELING: {len(anomalies['dns_tunneling'])} suspicious flows")
            for dns in anomalies['dns_tunneling'][:5]:
                lines.append(f"    └─ {dns['flow']}")
                lines.append(f"       Query rate: {dns['query_rate']:.1f} qps, "
                           f"Total: {dns['total_queries']}")
                
        # ICMP tunneling
        if anomalies.get('icmp_tunneling'):
            lines.append(f"\n🔴 ICMP TUNNELING: {len(anomalies['icmp_tunneling'])} suspicious flows")
            for icmp in anomalies['icmp_tunneling'][:5]:
                lines.append(f"    └─ [{icmp['confidence']}] {icmp['flow']}")
                lines.append(f"       Avg size: {icmp['avg_size']:.0f}B, "
                           f"Total: {icmp['total_bytes']/1024:.1f}KB, "
                           f"Packets: {icmp['packets']}")
                lines.append(f"       Indicators: {', '.join(icmp['reasons'])}")
        
        # Slowloris attacks
        if anomalies.get('slowloris'):
            lines.append(f"\n⚠️  SLOWLORIS ATTACK: {len(anomalies['slowloris'])} targets")
            for slow in anomalies['slowloris'][:5]:
                lines.append(f"    └─ [{slow['confidence']}] Target: {slow['target']}")
                lines.append(f"       Incomplete: {slow['incomplete_connections']}/{slow['total_connections']} "
                           f"({slow['incomplete_ratio']*100:.1f}%), "
                           f"Sources: {slow['unique_sources']}")
        
        # Fragmentation attacks
        if anomalies.get('fragmentation'):
            lines.append(f"\n⚠️  FRAGMENTATION ATTACK: {len(anomalies['fragmentation'])} targets")
            for frag in anomalies['fragmentation'][:5]:
                lines.append(f"    └─ [{frag['confidence']}] Target: {frag['target']}")
                lines.append(f"       Fragments: {frag['fragment_count']}, "
                           f"Sources: {frag['unique_sources']}")
        
        # Protocol anomalies
        if anomalies.get('protocol_anomalies'):
            lines.append(f"\n⚠️  PROTOCOL ANOMALIES: {len(anomalies['protocol_anomalies'])} flows")
            for anom in anomalies['protocol_anomalies'][:3]:
                lines.append(f"    └─ {anom['flow']}")
                lines.append(f"       Expected {anom['expected_proto']}, got {anom['actual_proto']}")
    
    lines.append("\n" + "=" * 80)
    
    return "\n".join(lines)

def main():
    if len(sys.argv) < 2:
        print("Usage: python improved_anomaly_detector.py <pcap> [options]")
        print("\nOptions:")
        print("  --json              Output in JSON format")
        print("  --output <file>     Save report to file")
        print("  --whitelist <ips>   Comma-separated IPs to ignore")
        print("  --sensitive         Use more sensitive detection (more false positives)")
        return
    
    pcap_path = sys.argv[1]
    output_format = 'text'
    output_file = None
    whitelist_ips = set()
    sensitive_mode = False
    
    # Parse arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--json':
            output_format = 'json'
        elif sys.argv[i] == '--output' and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
            i += 1
        elif sys.argv[i] == '--whitelist' and i + 1 < len(sys.argv):
            whitelist_ips = set(sys.argv[i + 1].split(','))
            i += 1
        elif sys.argv[i] == '--sensitive':
            sensitive_mode = True
        i += 1
    
    print(f"[+] Analyzing PCAP: {pcap_path}")
    packets, flows, errors = parse_pcap(pcap_path, whitelist_ips)
    
    if errors > 0:
        print(f"[!] Skipped {errors} malformed packets")
    
    if not packets:
        print("[!] No packets found in PCAP")
        return
    
    print(f"[+] Loaded {len(packets)} packets in {len(flows)} flows")
    
    # Build internal IP list after parsing PCAP
    ip_counter = Counter()
    for flow in flows.values():
        ip_counter[flow.key.src_ip] += 1
        ip_counter[flow.key.dst_ip] += 1

    internal_ips = set(ip for ip in ip_counter if is_private(ip))


def main():
    if len(sys.argv) < 2:
        print("Usage: python improved_anomaly_detector.py <pcap> [options]")
        print("\nOptions:")
        print("  --json              Output in JSON format")
        print("  --output <file>     Save report to file")
        print("  --whitelist <ips>   Comma-separated IPs to ignore")
        print("  --sensitive         Use more sensitive detection (more false positives)")
        return
    
    pcap_path = sys.argv[1]
    output_format = 'text'
    output_file = None
    whitelist_ips = set()
    sensitive_mode = False
    
    # Parse arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--json':
            output_format = 'json'
        elif sys.argv[i] == '--output' and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
            i += 1
        elif sys.argv[i] == '--whitelist' and i + 1 < len(sys.argv):
            whitelist_ips = set(sys.argv[i + 1].split(','))
            i += 1
        elif sys.argv[i] == '--sensitive':
            sensitive_mode = True
        i += 1
    
    print(f"[+] Analyzing PCAP: {pcap_path}")
    packets, flows, errors = parse_pcap(pcap_path, whitelist_ips)
    
    if errors > 0:
        print(f"[!] Skipped {errors} malformed packets")
    
    if not packets:
        print("[!] No packets found in PCAP")
        return
    
    print(f"[+] Loaded {len(packets)} packets in {len(flows)} flows")
    
    # Build internal IP list
    ip_counter = Counter()
    for flow in flows.values():
        ip_counter[flow.key.src_ip] += 1
        ip_counter[flow.key.dst_ip] += 1
    
    internal_ips = set(ip for ip in ip_counter if is_private_ip(ip))
    print(f"[+] Identified {len(internal_ips)} internal IP addresses")
    
    # Calculate baseline statistics
    print("[+] Calculating baseline statistics...")
    baseline = calculate_baseline(flows)
    if '--debug' in sys.argv:
        debug_flows(flows, internal_ips)
    
    # Perform anomaly detection
    print("[+] Running anomaly detection...")
    
    # Adjust thresholds based on mode
    if sensitive_mode:
        size_threshold = 2.5
        port_scan_threshold = 8
        syn_threshold = 30
        cv_threshold = 0.3
        min_beacon_packets = 8
    else:
        size_threshold = 3.0  # More lenient
        port_scan_threshold = 12  # Lower threshold
        syn_threshold = 40
        cv_threshold = 0.25  # More lenient
        min_beacon_packets = 10
    
    sizes = [p['size'] for p in packets]
    size_anomalies, size_median, size_mad = detect_size_anomalies(sizes, size_threshold)
    
    port_scanning = detect_port_scanning(flows, threshold=port_scan_threshold)
    syn_floods = detect_syn_flood(flows, syn_threshold=syn_threshold)
    data_exfil = detect_data_exfiltration(flows, internal_ips, baseline)
    beaconing = detect_beaconing(flows, min_packets=min_beacon_packets, cv_threshold=cv_threshold)
    dns_tunneling = detect_dns_tunneling(flows)
    icmp_tunneling = detect_icmp_tunneling(flows)
    slowloris = detect_slowloris(flows)
    fragmentation = detect_fragmentation_attack(flows)
    proto_anomalies = detect_protocol_anomalies(flows)
    
    # Generate statistics
    stats = analyze_traffic_statistics(packets, flows)
    
    # Compile anomalies
    anomalies = {
        'size_anomalies': size_anomalies,
        'size_median': size_median,
        'size_mad': size_mad,
        'port_scanning': port_scanning,
        'syn_floods': syn_floods,
        'data_exfiltration': data_exfil,
        'beaconing': beaconing,
        'dns_tunneling': dns_tunneling,
        'icmp_tunneling': icmp_tunneling,
        'slowloris': slowloris,
        'fragmentation': fragmentation,
        'protocol_anomalies': proto_anomalies
    }
    
    # Generate report
    report = generate_report(packets, flows, anomalies, stats, output_format)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(report)
        print(f"[+] Report saved to: {output_file}")
    else:
        print(report)

if __name__ == "__main__":
    main()