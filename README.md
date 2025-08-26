Packet Sniffer & Traffic Analyzer
Overview

Packet Sniffer & Traffic Analyzer is an advanced Python-based tool designed for network monitoring, traffic analysis, and real-time threat detection. It captures network packets, analyzes traffic patterns, identifies potential security threats, and provides real-time alerts via Discord. This project is ideal for cybersecurity enthusiasts, network administrators, and students learning defensive security.

Features
Packet Capture

Capture incoming and outgoing network traffic.

Save captured packets in .pcap format for detailed analysis.

Configurable number of packets to capture and timeout duration.

Traffic Analysis

Analyze captured traffic to generate protocol and service distributions.

Detect large packets, potential port scans, flooding activity, and unusual network patterns.

Top source/destination IPs and ports identification.

Optional visual charts for protocol distribution.

Threat Detection

SSH Brute Force Detection: Monitors repeated failed login attempts on port 22.

DOS and DDoS Detection: Detects high-volume traffic to web servers (ports 80, 443) from single or multiple IPs.

SQL Injection Detection: Scans HTTP and database traffic for SQL injection patterns.

Real-time alerts via Discord for detected attacks.

Logs detailed attack information in JSON files for forensic analysis.

IP Intelligence

Provides geolocation, ISP, and other information for source and destination IPs.

Caches IP information locally for efficiency.

Handles public and private IPs separately.

Logging & Reporting

JSON summary of all captured packets, analysis results, and detected threats.

Separate JSON log for detailed attack reports.

Discord webhook notifications for real-time alerts.

Installation

Clone the repository

git clone 






