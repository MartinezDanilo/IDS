from scapy.all import sniff, IP, TCP, UDP
import requests
import time
import sys
import os
import socket
import json
from datetime import datetime

# Check if running with admin privileges
if not os.name == 'nt':
    print("This script is designed for Windows only")
    sys.exit(1)

try:
    # Try to create a raw socket to check permissions
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    test_socket.close()
except PermissionError:
    print("\nError: This script requires administrator privileges to run.")
    print("Please run it as administrator:")
    print("1. Right-click on Python or your terminal")
    print("2. Select 'Run as administrator'")
    print("3. Then run the script again")
    sys.exit(1)

SUBMIT_URL = "http://localhost/maltrail-php/public/submit.php"

def extract_features(pkt):
    """Extract features from packet for classification"""
    features = {
        'src_ip': pkt[IP].src,
        'dst_ip': pkt[IP].dst,
        'proto': pkt[IP].proto,
        'packet_size': len(pkt),
        'sport': 0,
        'dport': 0,
        'flags': 0
    }
    
    # Convert protocol number to name
    proto_map = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        47: 'GRE',
        58: 'IPv6-ICMP'
    }
    features['proto_name'] = proto_map.get(pkt[IP].proto, 'Unknown')
    
    if TCP in pkt:
        features['sport'] = pkt[TCP].sport
        features['dport'] = pkt[TCP].dport
        features['flags'] = pkt[TCP].flags
    elif UDP in pkt:
        features['sport'] = pkt[UDP].sport
        features['dport'] = pkt[UDP].dport
    
    return features

def process_packet(pkt):
    try:
        if IP in pkt:
            features = extract_features(pkt)
            
            # Send all features including proto_name to the web interface
            try:
                response = requests.post(SUBMIT_URL, json={
                    'features': [
                        features['proto'],
                        features['packet_size'],
                        features['sport'],
                        features['dport'],
                        int(features['flags'])  # Convert flags to integer
                    ],
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': features['src_ip'],  # Changed from 'ip' to 'src_ip'
                    'proto_name': features['proto_name']
                })
                
                if response.status_code != 200:
                    print(f"Error: Classifier returned status {response.status_code}")
            except Exception as e:
                print(f"Error submitting features: {e}")
    except Exception as e:
        print(f"Error processing packet: {e}")

if __name__ == "__main__":
    try:
        print("Starting packet sniffing with Naive Bayes classifier...")
        sniff(filter="ip", prn=process_packet, store=0)
    except Exception as e:
        print(f"Error in sniffer: {e}")
