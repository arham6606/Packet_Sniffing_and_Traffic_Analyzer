#🚀 Packet Sniffer & Traffic Analyzer

An advanced Python-based tool for network monitoring, traffic analysis, and real-time threat detection.

Capture, analyze, and visualize network packets while detecting attacks like SSH brute force, DOS/DDoS, and SQL injection, with real-time Discord alerts.

#🛠 Features
##📦 Packet Capture

Capture incoming/outgoing network traffic.

Save packets in .pcap format.

Configurable number of packets and timeout.

#📊 Traffic Analysis

Generate protocol & service distributions.

Detect large packets, port scans, floods, and unusual patterns.

Identify top source/destination IPs & ports.

Optional charts for protocol distribution.

#⚠️ Threat Detection

SSH Brute Force Detection: Monitors repeated failed login attempts on port 22.

DOS/DDoS Detection: Detects high-volume HTTP(S) traffic.

SQL Injection Detection: Scans HTTP & DB traffic for attack patterns.

Real-time alerts via Discord.

Detailed attack logs in JSON files.

#🌐 IP Intelligence

Provides geolocation, ISP, and other info for source & destination IPs.

Caches IP info locally for faster queries.

Differentiates public vs private IPs.

#📝 Logging & Reporting

JSON summary of captured packets and detected attacks.

Detailed JSON logs for forensic analysis.

Optional charts saved as images for visual inspection.

#⚡ Installation

git clone [https://github.com/arham6606/Packet_Sniffing_and_Traffic_Analyzer.git]
pip install -r requirements.txt

##Dependencies:

scapy

requests

matplotlib

#▶️ Usage

Run the main program: sudo python3 src.main

Input the prompts:

Number of packets to capture.

Output filename for .pcap.

Analysis filename for JSON summary.

Program automatically creates directories:

log/ → stores .pcap and Discord logs.

data/ → stores JSON summaries, attack logs, and IP cache.

##View output:

.pcap file with captured packets.

JSON summary and detailed attack logs.

Optional protocol distribution chart.

Real-time Discord alerts for attacks.

##<details> <summary>Example Output</summary>
📊 Top 5 Source IPs:
   192.168.1.100: 50 packets
📊 Top 5 Destination Ports:
   Port 80: 200 packets
⚠️ Possible port scan detected from 192.168.1.101
⚠️ SSH Brute Force suspected from 203.0.113.45 (15 attempts in last 60s)
🚨 SQL Injection attempt detected from 198.51.100.22
 ##</details>

#📂 Project Structure

packet-sniffer-analyzer/
│
├── main.py                  # Entry point
├── src/
│   ├── capture.py           # Packet capture logic
│   ├── analyzer.py          # Network analysis logic
│   ├── analyzer_helper.py   # Helper functions and logging
│   ├── discord_alert.py     # Discord webhook notifications
│   ├── ip_location.py       # IP geolocation and caching
│   ├── sql_injection.py     # SQL injection detection
│   └── application_layer_attack.py  # DOS, DDOS, SSH brute force detection
├── log/                     # PCAP files and Discord alert logs
└── data/                    # JSON summaries, attack logs, and IP cache

#🔧 Customization

Discord Webhook: Update DISCORD_WEBHOOK in discord_alert.py.

Port/Protocol Settings: Modify SERVICE_PROTOCOLS and PROTOCOLS_MAPPING.

Attack Thresholds: Adjust in application_layer_attack.py.

#🤝 Contributing

Add new attack detection modules.

Improve visualizations or charts.

Optimize packet capture performance.

Submit bug fixes or pull requests.

#🔗 Connect with Me

##You can connect with me on LinkedIn:[www.linkedin.com/in/-arham]
