import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import scapy.all as scapy
import pyshark
import re
import json
import subprocess
from collections import Counter

# 1. Network Traffic Analysis (PCAP File Analysis)
def analyze_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    protocols = Counter()
    src_ips = Counter()
    dst_ips = Counter()

    for packet in cap:
        try:
            if hasattr(packet, 'ip'):
                protocols[packet.highest_layer] += 1
                src_ips[packet.ip.src] += 1
                dst_ips[packet.ip.dst] += 1
        except AttributeError:
            continue
    
    cap.close()
    return {
        "Top Protocols": protocols.most_common(10),
        "Top Source IPs": src_ips.most_common(10),
        "Top Destination IPs": dst_ips.most_common(10),
    }

# 2. Log File Analyzer (SIEM-style Log Parsing)
def parse_log_file(log_file):
    failed_logins = []
    login_pattern = re.compile(r'Failed password for (\w+) from ([0-9\.]+)')
    
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = login_pattern.search(line)
            if match:
                failed_logins.append(match.group(2))
    
    ip_counter = Counter(failed_logins)
    return ip_counter.most_common(10)

# 3. Vulnerability Scan Report Analysis (Nmap Output Parser)
def parse_nmap_report(nmap_json_file):
    with open(nmap_json_file, 'r') as f:
        data = json.load(f)
    
    vuln_summary = []
    for host in data.get('hosts', []):
        for service in host.get('ports', []):
            if service.get('state') == 'open':
                vuln_summary.append((host['ip'], service['portid'], service['service']['name']))
    
    return vuln_summary

# 4. Malware Analysis Data Extraction (Dummy Implementation)
def analyze_malware_logs(log_file):
    suspicious_patterns = ["registry change", "file modified", "unauthorized connection"]
    alerts = []
    
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if any(pattern in line.lower() for pattern in suspicious_patterns):
                alerts.append(line.strip())
    
    return alerts

# 5. Network Performance & Latency Analysis
def monitor_latency(host, count=10):
    latencies = []
    for i in range(count):
        packet = scapy.IP(dst=host)/scapy.ICMP()
        reply = scapy.sr1(packet, timeout=1, verbose=False)
        if reply:
            latencies.append(reply.time)
        else:
            latencies.append(None)
    
    plt.plot(latencies, marker='o')
    plt.xlabel("Ping Attempt")
    plt.ylabel("Response Time (s)")
    plt.title(f"Latency to {host}")
    plt.show()

# 6. User Authentication Log Analysis
def analyze_authentication_logs(log_file):
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        logs = f.readlines()
    
    failed_logins = [line for line in logs if "Failed password" in line]
    failed_attempts = Counter(re.findall(r'from ([0-9\.]+)', '\n'.join(failed_logins)))
    
    return failed_attempts.most_common(10)

# 7. Cybersecurity Incident Timeline Generator
def generate_incident_timeline(log_file):
    events = []
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            timestamp_match = re.search(r'\w{3} \d{2} \d{2}:\d{2}:\d{2}', line)
            if timestamp_match:
                events.append((timestamp_match.group(0), line.strip()))
    
    df = pd.DataFrame(events, columns=["Timestamp", "Event"])
    df.to_csv("incident_timeline.csv", index=False)
    print("Incident timeline saved as incident_timeline.csv")

# 8. Network Diagnostic Script
def diagnose_network():
    print("Checking network connectivity...")
    try:
        subprocess.run(["ping", "-c", "4", "8.8.8.8"], check=True)
        print("Internet is working.")
    except subprocess.CalledProcessError:
        print("No internet connection.")
    
    print("Checking DHCP configuration...")
    try:
        subprocess.run(["ipconfig" if subprocess.os.name == "nt" else "ifconfig"], check=True)
    except Exception as e:
        print("Error retrieving network configuration:", e)
    
    print("Checking domain connectivity...")
    try:
        subprocess.run(["nslookup", "yourdomain.com"], check=True)
        print("DNS resolution is working.")
    except subprocess.CalledProcessError:
        print("Cannot resolve domain name.")

if __name__ == "__main__":
    diagnose_network()
    print("Analyzing network traffic...")
    print(analyze_pcap("network_traffic.pcap"))
    
    print("Parsing system logs...")
    print(parse_log_file("auth.log"))
    
    print("Analyzing Nmap scan report...")
    print(parse_nmap_report("nmap_scan.json"))
    
    print("Analyzing malware logs...")
    print(analyze_malware_logs("malware_log.txt"))
    
    print("Monitoring network latency...")
    monitor_latency("8.8.8.8")
    
    print("Analyzing authentication logs...")
    print(analyze_authentication_logs("auth.log"))
    
    print("Generating cybersecurity incident timeline...")
    generate_incident_timeline("security_logs.txt")
