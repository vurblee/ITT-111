import os
import pyshark
import time
import subprocess
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import scapy.all as scapy
import re
import json
from collections import Counter

# Define Paths
pcap_file = r"C:\Users\aslan\pyscripts\network_traffic.pcap"
log_dir = r"C:\Users\aslan\pyscripts\logs"
log_file = os.path.join(log_dir, "network_analysis.log")
security_log_file = os.path.join(log_dir, "security_logs.txt")
nmap_json_file = r"C:\Users\aslan\pyscripts\nmap_scan.json"

# Ensure log directory exists
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Function to log messages (UTF-8 encoding)
def write_log(message, log_type="general"):
    log_path = log_file if log_type == "general" else os.path.join(log_dir, f"{log_type}.log")

    with open(log_path, "a", encoding="utf-8") as log:
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

    print(message)

# 1️⃣ Vulnerability Scan Report Analysis (Nmap Output)
def parse_nmap_report(nmap_json_file):
    if not os.path.exists(nmap_json_file):
        write_log(f"⚠ Warning: {nmap_json_file} not found. Skipping Nmap analysis.", "security")
        return []

    try:
        with open(nmap_json_file, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        write_log(f"⚠ Error: Invalid JSON format in {nmap_json_file}.", "security")
        return []

    vuln_summary = []
    for host in data.get('hosts', []):
        for service in host.get('ports', []):
            if service.get('state') == 'open':
                vuln_summary.append((host['ip'], service['portid'], service['service']['name']))
                write_log(f"Vulnerability Found: {host['ip']} - Port {service['portid']} ({service['service']['name']})", "security")

    return vuln_summary

# 2️⃣ Cybersecurity Incident Timeline Generator
def generate_incident_timeline(log_file):
    if not os.path.exists(log_file):
        write_log(f"⚠ Warning: {log_file} not found. No security events to process.", "security")
        return

    events = []
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            timestamp_match = re.search(r'\w{3} \d{2} \d{2}:\d{2}:\d{2}', line)
            if timestamp_match:
                events.append((timestamp_match.group(0), line.strip()))

    if events:
        df = pd.DataFrame(events, columns=["Timestamp", "Event"])
        df.to_csv("incident_timeline.csv", index=False)
        write_log("Incident timeline saved as incident_timeline.csv", "security")
    else:
        write_log("⚠ No security events detected.", "security")

# 3️⃣ Automated Packet Capture Using Wireshark (Tshark)
def capture_network_packets(interface="Wi-Fi", duration=10):
    write_log(f"Starting packet capture on {interface} for {duration} seconds...")
    tshark_cmd = f'tshark -i "{interface}" -w "{pcap_file}" -a duration:{duration}'
    try:
        subprocess.run(tshark_cmd, shell=True, check=True)
        write_log(f"Packet capture completed: {pcap_file}")
    except subprocess.CalledProcessError as e:
        write_log(f"Error running Tshark: {e}")
        return False
    return True

# 4️⃣ Network Traffic Analysis (PCAP File)
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

# 5️⃣ Network Performance & Latency Analysis
def monitor_latency(host, count=10):
    latencies = []
    write_log(f"📡 Monitoring latency to {host} for {count} pings...", "network")

    for i in range(count):
        packet = scapy.IP(dst=host)/scapy.ICMP()
        reply = scapy.sr1(packet, timeout=1, verbose=False)

        if reply:
            latency = reply.time
            latencies.append(latency)
            write_log(f"Ping {i+1}/{count}: {latency:.4f} seconds", "network")
        else:
            latencies.append(None)
            write_log(f"Ping {i+1}/{count}: Request timed out", "network")

        time.sleep(1)

    df = pd.DataFrame({"Ping #": list(range(1, count+1)), "Latency (s)": latencies})
    df.to_csv("latency_results.csv", index=False)
    write_log("✅ Latency results saved to latency_results.csv", "network")

    plt.plot(df["Ping #"], df["Latency (s)"], marker='o')
    plt.xlabel("Ping Attempt")
    plt.ylabel("Response Time (s)")
    plt.title(f"Latency to {host}")
    plt.savefig("latency_graph.png")
    write_log("📊 Latency graph saved as latency_graph.png", "network")

# Main Execution
if __name__ == "__main__":
    write_log("🚀 Starting Cybersecurity Analysis...")

    # Run Vulnerability Scan First
    write_log("🔍 Running Nmap vulnerability scan analysis...")
    vulnerabilities = parse_nmap_report(nmap_json_file)
    if vulnerabilities:
        print(vulnerabilities)

    # Generate Incident Timeline **AFTER** Vulnerability Scan
    write_log("🕒 Generating cybersecurity incident timeline...")
    generate_incident_timeline(security_log_file)

    # Capture Network Packets **AFTER** Vulnerability Scan and Timeline Generation
    if capture_network_packets():
        write_log("📊 Analyzing captured network traffic...")
        print(analyze_pcap(pcap_file))

    # Monitor Network Latency **Last**
    write_log("🌍 Monitoring network latency...")
    monitor_latency("8.8.8.8")

    write_log("✅ Cybersecurity Analysis Completed!")
