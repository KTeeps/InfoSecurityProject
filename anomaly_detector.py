#!/usr/bin/env python3
"""
Advanced Network Anomaly Detector with Flow Analysis
Addresses limitations: protocol analysis, flow tracking, context-aware detection,
time-series analysis, and JSON export for CAPE integration
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
    
    def add_packet(self, ts, size, flags=None):
        if self.start_time is None:
            self.start_time = ts
        self.end_time = ts
        self.packets.append((ts, size, flags))
        self.sizes.append(size)
        self.timestamps.append(ts)
        self.tcp_flags.append(flags)
        self.total_bytes += size
    
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

def detect_size_anomalies(sizes, threshold=3.0):
    """Z-score based size anomaly detection"""
    if len(sizes) < 2:
        return [], 0, 0
    
    mean = np.mean(sizes)
    std = np.std(sizes)
    
    if std == 0:
        return [], mean, 0
    
    anomalies = []
    for i, s in enumerate(sizes):
        z = (s - mean) / std
        if abs(z) > threshold:
            anomalies.append((i, s, z))
    
    return anomalies, mean, std

def detect_port_scanning(flows, threshold=20):
    """Detect port scanning: many connections to different ports from same source"""
    src_to_dst_ports = defaultdict(set)
    
    for flow_key, flow in flows.items():
        if flow.key.proto == "TCP":
            src = flow.key.src_ip
            dst_port = flow.key.dst_port
            src_to_dst_ports[src].add(dst_port)
    
    scanners = []
    for src, ports in src_to_dst_ports.items():
        if len(ports) > threshold:
            scanners.append((src, len(ports)))
    
    return scanners

def detect_syn_flood(flows):
    """Detect SYN flood: many SYN packets without corresponding ACK"""
    syn_floods = []
    
    for flow_key, flow in flows.items():
        if flow.key.proto != "TCP":
            continue
        
        syn_count = 0
        ack_count = 0
        
        for flags in flow.tcp_flags:
            if flags is not None:
                if flags & dpkt.tcp.TH_SYN:
                    syn_count += 1
                if flags & dpkt.tcp.TH_ACK:
                    ack_count += 1
        
        # If many SYNs but few ACKs, potential SYN flood
        if syn_count > 10 and ack_count < syn_count * 0.2:
            syn_floods.append({
                'flow': str(flow_key),
                'syn_count': syn_count,
                'ack_count': ack_count,
                'packets': len(flow.packets)
            })
    
    return syn_floods

def is_known_service(dst_ip):
    """Check if destination is a known legitimate service"""
    known_services = {
        # Public DNS
        "8.8.8.8", "8.8.4.4",  # Google DNS
        "1.1.1.1", "1.0.0.1",  # Cloudflare DNS
        "9.9.9.9",              # Quad9 DNS
        # Add more as needed
    }
    
    # Check if IP starts with known service ranges
    known_ranges = [
        "8.8.",      # Google
        "1.1.",      # Cloudflare
        "1.0.",      # Cloudflare
    ]
    
    if dst_ip in known_services:
        return True
    
    for range_prefix in known_ranges:
        if dst_ip.startswith(range_prefix):
            return True
    
    return False

def detect_data_exfiltration(flows, internal_ips, size_threshold=500000, rate_threshold=50000, packet_threshold=50):
    """
    Detect potential data exfiltration with improved heuristics
    
    Key changes:
    - Ignore ICMP traffic (usually just pings)
    - Focus on TCP/UDP flows with sustained high volume
    - Require minimum packet count to avoid false positives
    - Higher thresholds for total bytes and rate
    - Stricter scoring system
    """
    exfil_candidates = []

    for flow_key, flow in flows.items():
        # Skip ICMP - typically not used for exfiltration
        if flow.key.proto == "ICMP":
            continue
        
        # Only examine outbound flows from internal networks
        if flow.key.src_ip not in internal_ips or flow.key.dst_ip in internal_ips:
            continue
        
        # Skip flows with too few packets (likely normal requests)
        if len(flow.packets) < packet_threshold:
            continue
        
        # Calculate score based on suspicious characteristics
        score = 0
        reasons = []
        
        # Very large total transfer (>500KB)
        if flow.total_bytes > size_threshold:
            score += 3
            reasons.append(f"large_transfer_{flow.total_bytes}_bytes")
        
        # High sustained transfer rate (>50KB/s)
        byte_rate = flow.get_byte_rate()
        if byte_rate > rate_threshold:
            score += 3
            reasons.append(f"high_rate_{byte_rate:.0f}_Bps")
        
        # Uncommon destination (not known service)
        if not is_known_service(flow.key.dst_ip):
            score += 2
            reasons.append("unknown_destination")
        
        # Off-hours activity (before 6am or after 10pm)
        if flow.start_time:
            start_dt = datetime.fromtimestamp(flow.start_time)
            if start_dt.hour < 6 or start_dt.hour >= 22:
                score += 1
                reasons.append("off_hours")
        
        # Unusual port for large transfers
        suspicious_ports = [443, 8080, 8443, 9090]  # Common exfil ports
        if flow.key.dst_port not in [80, 443] and flow.total_bytes > 100000:
            score += 1
            reasons.append(f"unusual_port_{flow.key.dst_port}")
        
        # Long duration with sustained activity
        duration = flow.get_duration()
        if duration > 60 and len(flow.packets) > 100:  # >1 min, >100 packets
            score += 2
            reasons.append(f"sustained_activity_{duration:.0f}s")

        # Flag if score is high enough (stricter threshold)
        if score >= 7:  # Increased from 5 to reduce false positives
            exfil_candidates.append({
                'flow': str(flow_key),
                'total_bytes': flow.total_bytes,
                'byte_rate': byte_rate,
                'duration': duration,
                'packets': len(flow.packets),
                'score': score,
                'reasons': reasons
            })

    return exfil_candidates


def detect_beaconing(flows, regularity_threshold=0.15):
    """Detect C2 beaconing: regular periodic communication"""
    beacons = []
    
    for flow_key, flow in flows.items():
        if len(flow.packets) < 5:
            continue
        
        inter_arrival = flow.get_inter_arrival_times()
        if len(inter_arrival) < 4:
            continue
        
        # Calculate coefficient of variation (std/mean)
        mean_iat = np.mean(inter_arrival)
        std_iat = np.std(inter_arrival)
        
        if mean_iat > 0:
            cv = std_iat / mean_iat
            
            # Low CV indicates regular intervals (beaconing)
            if cv < regularity_threshold:
                beacons.append({
                    'flow': str(flow_key),
                    'packets': len(flow.packets),
                    'mean_interval': mean_iat,
                    'regularity_score': 1 - cv,
                    'duration': flow.get_duration()
                })
    
    return beacons

def detect_protocol_anomalies(flows):
    """Detect unusual protocol usage"""
    anomalies = []
    
    # Well-known ports and expected protocols
    expected_protocols = {
        80: 'TCP',   # HTTP
        443: 'TCP',  # HTTPS
        53: 'UDP',   # DNS
        22: 'TCP',   # SSH
        21: 'TCP',   # FTP
        25: 'TCP',   # SMTP
    }
    
    for flow_key, flow in flows.items():
        dst_port = flow.key.dst_port
        proto = flow.key.proto
        
        # Check if protocol matches expected for well-known port
        if dst_port in expected_protocols:
            if proto != expected_protocols[dst_port]:
                anomalies.append({
                    'flow': str(flow_key),
                    'expected_proto': expected_protocols[dst_port],
                    'actual_proto': proto,
                    'packets': len(flow.packets)
                })
    
    return anomalies

def analyze_traffic_statistics(packets, flows):
    """Generate overall traffic statistics"""
    if not packets:
        return {}
    
    proto_counts = Counter([p['proto'] for p in packets])
    total_packets = len(packets)
    
    sizes = [p['size'] for p in packets]
    timestamps = [p['timestamp'] for p in packets]
    
    duration = max(timestamps) - min(timestamps) if timestamps else 0
    
    # Top talkers
    src_counts = Counter([p['src_ip'] for p in packets])
    dst_counts = Counter([p['dst_ip'] for p in packets])
    
    # Port statistics
    dst_ports = [p['dst_port'] for p in packets if p['dst_port'] > 0]
    port_counts = Counter(dst_ports)
    
    stats = {
        'total_packets': total_packets,
        'total_flows': len(flows),
        'duration': duration,
        'packets_per_second': total_packets / duration if duration > 0 else 0,
        'protocol_distribution': dict(proto_counts),
        'avg_packet_size': np.mean(sizes),
        'median_packet_size': np.median(sizes),
        'top_sources': src_counts.most_common(5),
        'top_destinations': dst_counts.most_common(5),
        'top_ports': port_counts.most_common(10)
    }
    
    return stats

def generate_report(packets, flows, anomalies, stats, output_format='text'):
    """Generate comprehensive analysis report"""
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
    lines.append("NETWORK TRAFFIC ANOMALY DETECTION REPORT")
    lines.append("=" * 80)
    lines.append(f"Analysis Time: {report['analysis_timestamp']}")
    lines.append("")
    
    # Statistics
    lines.append("TRAFFIC STATISTICS")
    lines.append("-" * 80)
    lines.append(f"Total Packets: {stats['total_packets']}")
    lines.append(f"Total Flows: {stats['total_flows']}")
    lines.append(f"Duration: {stats['duration']:.2f} seconds")
    lines.append(f"Packet Rate: {stats['packets_per_second']:.2f} pkt/s")
    lines.append(f"Avg Packet Size: {stats['avg_packet_size']:.2f} bytes")
    lines.append(f"Median Packet Size: {stats['median_packet_size']:.2f} bytes")
    lines.append("")
    
    lines.append("Protocol Distribution:")
    for proto, count in stats['protocol_distribution'].items():
        pct = (count / stats['total_packets']) * 100
        lines.append(f"  {proto}: {count} ({pct:.1f}%)")
    lines.append("")
    
    # Anomalies
    lines.append("DETECTED ANOMALIES")
    lines.append("-" * 80)
    
    # Size anomalies
    if anomalies['size_anomalies']:
        lines.append(f"\n[!] Packet Size Anomalies: {len(anomalies['size_anomalies'])} found")
        lines.append(f"    Mean: {anomalies['size_mean']:.2f} bytes, Std: {anomalies['size_std']:.2f}")
        for idx, size, z in anomalies['size_anomalies'][:10]:  # Show top 10
            lines.append(f"    Packet #{idx}: {size} bytes (z-score: {z:.2f})")
    
    # Port scanning
    if anomalies['port_scanning']:
        lines.append(f"\n[!] Port Scanning Detected: {len(anomalies['port_scanning'])} sources")
        for src, port_count in anomalies['port_scanning'][:5]:
            lines.append(f"    {src} scanned {port_count} ports")
    
    # SYN floods
    if anomalies['syn_floods']:
        lines.append(f"\n[!] Potential SYN Floods: {len(anomalies['syn_floods'])} flows")
        for flood in anomalies['syn_floods'][:5]:
            lines.append(f"    {flood['flow']}: {flood['syn_count']} SYNs, {flood['ack_count']} ACKs")
    
    # Data exfiltration
    if anomalies['data_exfiltration']:
        lines.append(f"\n[!] Potential Data Exfiltration: {len(anomalies['data_exfiltration'])} flows")
        for exfil in anomalies['data_exfiltration'][:5]:
            lines.append(f"    {exfil['flow']}")
            lines.append(f"      Total: {exfil['total_bytes']} bytes, Rate: {exfil['byte_rate']:.2f} B/s")
    
    # Beaconing
    if anomalies['beaconing']:
        lines.append(f"\n[!] Potential C2 Beaconing: {len(anomalies['beaconing'])} flows")
        for beacon in anomalies['beaconing'][:5]:
            lines.append(f"    {beacon['flow']}")
            lines.append(f"      Interval: {beacon['mean_interval']:.3f}s, Regularity: {beacon['regularity_score']:.3f}")
    
    # Protocol anomalies
    if anomalies['protocol_anomalies']:
        lines.append(f"\n[!] Protocol Anomalies: {len(anomalies['protocol_anomalies'])} flows")
        for proto_anom in anomalies['protocol_anomalies'][:5]:
            lines.append(f"    {proto_anom['flow']}")
            lines.append(f"      Expected {proto_anom['expected_proto']}, got {proto_anom['actual_proto']}")
    
    lines.append("\n" + "=" * 80)
    
    return "\n".join(lines)


def is_private(ip):
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

def main():
    if len(sys.argv) < 2:
        print("Usage: python advanced_anomaly_detector.py <pcap> [options]")
        print("\nOptions:")
        print("  --json              Output in JSON format")
        print("  --output <file>     Save report to file")
        print("  --threshold <n>     Z-score threshold (default: 3.0)")
        print("  --whitelist <ips>   Comma-separated IPs to ignore")
        return
    
    known_destinations = {
    "8.8.8.8",  # Google DNS
    "13.35.0.0/16",  # AWS services
    "40.112.0.0/16", # Azure services
}
    
    pcap_path = sys.argv[1]
    output_format = 'text'
    output_file = None
    threshold = 3.0
    whitelist_ips = set()
    
    # Parse arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--json':
            output_format = 'json'
        elif sys.argv[i] == '--output' and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
            i += 1
        elif sys.argv[i] == '--threshold' and i + 1 < len(sys.argv):
            threshold = float(sys.argv[i + 1])
            i += 1
        elif sys.argv[i] == '--whitelist' and i + 1 < len(sys.argv):
            whitelist_ips = set(sys.argv[i + 1].split(','))
            i += 1
        i += 1
    
    print(f"[+] Parsing PCAP: {pcap_path}")
    packets, flows, errors = parse_pcap(pcap_path, whitelist_ips)
    
    if errors > 0:
        print(f"[!] Skipped {errors} malformed packets")
    
    if not packets:
        print("[!] No packets found in PCAP")
        return
    
    
    print(f"[+] Loaded {len(packets)} packets in {len(flows)} flows")
    
    # Perform analysis
    print("[+] Analyzing traffic...")
    
    sizes = [p['size'] for p in packets]
    size_anomalies, size_mean, size_std = detect_size_anomalies(sizes, threshold)
    
    # Build internal IP list after parsing PCAP
    ip_counter = Counter()
    for flow in flows.values():
        ip_counter[flow.key.src_ip] += 1
        ip_counter[flow.key.dst_ip] += 1

    internal_ips = set(ip for ip in ip_counter if is_private(ip))

    
    port_scanning = detect_port_scanning(flows)
    syn_floods = detect_syn_flood(flows)
    data_exfil = detect_data_exfiltration(flows, internal_ips)
    beaconing = detect_beaconing(flows)
    proto_anomalies = detect_protocol_anomalies(flows)
    
    stats = analyze_traffic_statistics(packets, flows)
    
    anomalies = {
        'size_anomalies': size_anomalies,
        'size_mean': size_mean,
        'size_std': size_std,
        'port_scanning': port_scanning,
        'syn_floods': syn_floods,
        'data_exfiltration': data_exfil,
        'beaconing': beaconing,
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
