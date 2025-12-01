"""
Wrapper module for anomaly_detector.py to integrate with Flask app
"""

import sys
import os
from collections import Counter
from anomaly_detector import (
    parse_pcap,
    calculate_baseline,
    detect_size_anomalies,
    detect_port_scanning,
    detect_syn_flood,
    detect_data_exfiltration,
    detect_beaconing,
    detect_dns_tunneling,
    detect_icmp_tunneling,
    detect_slowloris,
    detect_fragmentation_attack,
    detect_protocol_anomalies,
    analyze_traffic_statistics,
    is_private_ip
)

def analyze_pcap(pcap_path, whitelist_ips=None):
    """
    Analyze PCAP file and return results in a format suitable for the web interface
    """
    if whitelist_ips is None:
        whitelist_ips = set()
    
    # Parse PCAP
    packets, flows, errors = parse_pcap(pcap_path, whitelist_ips)
    
    if not packets:
        return {
            'error': 'No packets found in PCAP',
            'packets': 0,
            'flows': 0
        }
    
    # Build internal IP list
    ip_counter = Counter()
    for flow in flows.values():
        ip_counter[flow.key.src_ip] += 1
        ip_counter[flow.key.dst_ip] += 1
    
    internal_ips = set(ip for ip in ip_counter if is_private_ip(ip))
    
    # Calculate baseline statistics
    baseline = calculate_baseline(flows)
    
    # Perform anomaly detection
    sizes = [p['size'] for p in packets]
    size_anomalies, size_median, size_mad = detect_size_anomalies(sizes, threshold=3.0)
    
    port_scanning = detect_port_scanning(flows, threshold=12)
    syn_floods = detect_syn_flood(flows, syn_threshold=40)
    data_exfil = detect_data_exfiltration(flows, internal_ips, baseline)
    beaconing = detect_beaconing(flows, min_packets=10, cv_threshold=0.25)
    dns_tunneling = detect_dns_tunneling(flows)
    icmp_tunneling = detect_icmp_tunneling(flows)
    slowloris = detect_slowloris(flows)
    fragmentation = detect_fragmentation_attack(flows)
    proto_anomalies = detect_protocol_anomalies(flows)
    
    # Generate statistics
    stats = analyze_traffic_statistics(packets, flows)
    
    # Compile results
    results = {
        'packets': len(packets),
        'flows': len(flows),
        'errors': errors,
        'internal_ips': len(internal_ips),
        'stats': stats,
        'anomalies': {
            'size_anomalies': [
                {
                    'index': idx,
                    'size': size,
                    'z_score': float(z)
                }
                for idx, size, z in size_anomalies[:20]  # Limit to top 20
            ],
            'size_median': float(size_median),
            'size_mad': float(size_mad),
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
    }
    
    return results