#!/usr/bin/env python3
"""
Quick test script to check all PCAP detections
"""

import subprocess
import sys
import os

def test_pcap(filename, expected_detections):
    """Test a PCAP file and check if expected detections occur"""
    if not os.path.exists(filename):
        print(f"❌ {filename} not found")
        return False
    
    print(f"\n{'='*80}")
    print(f"Testing: {filename}")
    print(f"Expected: {', '.join(expected_detections)}")
    print('='*80)
    
    result = subprocess.run(
        ['python3', 'anomaly_detector.py', filename],
        capture_output=True,
        text=True
    )
    
    output = result.stdout
    
    # Check for expected detections
    found = []
    missing = []
    
    detection_keywords = {
        'port_scan': 'PORT SCANNING',
        'syn_flood': 'SYN FLOOD',
        'exfiltration': 'DATA EXFILTRATION',
        'dns_tunnel': 'DNS TUNNELING',
        'icmp_tunnel': 'ICMP TUNNELING',
        'slowloris': 'SLOWLORIS',
        'fragmentation': 'FRAGMENTATION',
    }
    
    for detection in expected_detections:
        keyword = detection_keywords.get(detection, detection.upper())
        if keyword in output:
            found.append(detection)
            print(f"✅ Found: {detection}")
        else:
            missing.append(detection)
            print(f"❌ Missing: {detection}")
    
    # Check for "NO ANOMALIES" when we expect clean traffic
    if 'normal' in expected_detections:
        if 'NO SIGNIFICANT ANOMALIES' in output:
            print("✅ Correctly identified as normal traffic")
            return True
        else:
            print("❌ False positives detected in normal traffic")
            return False
    
    success = len(missing) == 0
    return success

def main():
    print("🔍 PCAP Anomaly Detection Test Suite")
    print("="*80)
    
    tests = [
        ('1_normal_traffic.pcap', ['normal']),
        ('2_port_scan.pcap', ['port_scan']),
        ('3_syn_flood.pcap', ['syn_flood']),
        ('4_exfiltration.pcap', ['exfiltration']),
        ('5_dns_tunneling.pcap', ['dns_tunnel']),
        ('6_icmp_tunnel.pcap', ['icmp_tunnel']),
        ('7_slowloris.pcap', ['slowloris']),
        ('8_fragmentation.pcap', ['fragmentation']),
        ('9_mixed_attacks.pcap', ['port_scan', 'exfiltration', 'dns_tunnel']),
    ]
    
    results = []
    for filename, expected in tests:
        success = test_pcap(filename, expected)
        results.append((filename, success))
    
    # Summary
    print("\n\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for filename, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {filename}")
    
    print(f"\nTotal: {passed}/{total} tests passed ({passed/total*100:.0f}%)")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print(f"\n⚠️  {total-passed} test(s) failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
