# Import required libraries
from datetime import datetime              # For handling timestamps
import json                                # For saving analysis results in JSON
import os                                  # For file and directory operations
from scapy.all import rdpcap               # For reading packets from a .pcap file
from collections import Counter, defaultdict  # For counting occurrences and mapping values
import logging                             # For logging runtime information
import matplotlib.pyplot as plt            # For data visualization (charts)
from scapy.all import IP, TCP, UDP         # For working with IP, TCP, and UDP headers
from scapy.utils import PcapReader         # For efficient packet reading (streaming packets)
from scapy.error import Scapy_Exception    # For handling Scapy-specific errors              
from src.application_layer_attack import Detect_DOS_Attack,Detect_DDOS_Attack,Detect_SSH_Brute_Force
from src.analyzer_helper import get_unique_filename,get_service_name,SERVICE_PROTOCOLS,PROTOCOLS_MAPPING
from src.ip_location import get_ip_info
from src.sql_injection import Detect_SQL_Injection


# Configure the root logger (should be set once in the program)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")




def analyze_network_traffic(output_file, analysis_file, chart):
    
    """
    Analyze packets from a PCAP file, extract insights, and optionally generate charts.

    Args:
        output_file (str): Path to the input PCAP file.
        analysis_file (str): Path to save JSON analysis results.
        chart (bool): Whether to generate protocol distribution charts.

    Returns:
        dict: Summary of the analysis results.
    """

    # --- Input validation ---
    if not output_file.endswith(".pcap"):
        raise ValueError("File must have a .pcap extension")
    if not os.path.exists(output_file):
        raise FileNotFoundError(f"File not found: {output_file}")
    if not os.access(output_file, os.R_OK):
        raise PermissionError(f"No read access to file: {output_file}")
    
    # --- Initialize counters and data structures ---
    protocols = Counter()
    source_ip = Counter()
    destination_ip = Counter()
    source_ports = Counter()
    destination_ports = Counter()
    service_protocols = Counter()
    packets_sizes = []
    ip_packet_times = defaultdict(list)
    source_ip_info = []
    destination_ip_info = []

    # Track capture duration
    start_time, end_time = None, None
    packets_count = 0
    port_scan_limit = 10 
    ip_to_ports = defaultdict(set)
    
    try:
        # Stream packets from the PCAP file (efficient memory usage)
        with PcapReader(output_file) as pcap:
            for packet in pcap:
                packets_count += 1
                packets_sizes.append(len(packet))
                
                # Track capture start and end time
                time_in_seconds = float(packet.time)
                if start_time is None:
                    start_time = time_in_seconds
                end_time = time_in_seconds
                
                # --- Extract IP layer information ---
                if IP in packet:
                    protocol_num = packet[IP].proto
                    protocol = PROTOCOLS_MAPPING.get(protocol_num, str(protocol_num))
                    
                    protocols[protocol] += 1
                    source_ip[packet[IP].src] += 1
                    destination_ip[packet[IP].dst] += 1

                    # Track packet timestamps for flood detection
                    source_ip_key = tuple(sorted(source_ip.items()))
                    ip_packet_times[source_ip_key].append(packet.time)
                    
                    lay = packet[TCP] if TCP in packet else packet[UDP]
                    ip_to_ports[packet[IP].src].add(lay.dport)
                
                else:
                    continue

                # --- Extract transport layer information ---
                if TCP in packet or UDP in packet:
                    layer = packet[TCP] if TCP in packet else packet[UDP]
                    source_ports[layer.sport] += 1
                    destination_ports[layer.dport] += 1

                    # ✅ Map port numbers to services (custom + system)
                    service = get_service_name(layer.sport) or get_service_name(layer.dport)
                    if service !="Unknown":
                        service_protocols[service]+=1
                
                #storing the DOS attack and to check if it is happening
                dos_attack_happening = Detect_DOS_Attack(layer.dport, packet[IP].src,time_in_seconds)
                #storing the DDOS attack to check if it is happening
                ddos_attack_happening = Detect_DDOS_Attack(layer.dport,packet[IP].src,time_in_seconds)
                #storing the SSH brute forcing attack if it is happeing
                ssh_attack_happening = Detect_SSH_Brute_Force(layer.dport,packet[IP].src,time_in_seconds)
                #storing detailed info about ip in file
                
                source_ip_info.append(packet[IP].src)
                destination_ip_info.append(packet[IP].dst)

                #sql injection detection
                if TCP in packet:
                    #gets the destination port and contents of HTTP
                    dport = packet[TCP].dport
                    payload = bytes(packet[TCP].payload)
                    sql_injection_happening = "None"


                    if payload:
                        try:
                            #conversion of binary into string
                            payload_string = payload.decode("utf-8",errors="ignore")

                            #webs server attacks
                            if dport in [80,443,8080]:
                                sql_injection_happening = Detect_SQL_Injection(payload,packet[IP].src,packet[IP].dst,time_in_seconds,dport)
                            
                            #DB server attacks
                            elif dport in [3306,1433,5432,1521]:
                                sql_injection_happening = Detect_SQL_Injection(payload,packet[IP].src,packet[IP].dst,time_in_seconds,dport)


                        
                        except Exception as e:
                            pass

    # --- Error handling ---
    except Scapy_Exception as e:
        logging.error(f"Scapy error: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected Error: {e}")
        return None 
    
    # --- Reporting Section ---
    print("📊 Top 5 Source IPs (most active senders):")
    for ip, count in source_ip.most_common(5):
        print(f"   {ip}: {count} packets")

    print("\n📊 Top 5 Destination IPs (most targeted hosts):")
    for ip, count in destination_ip.most_common(5):
        print(f"   {ip}: {count} packets")

    print("\n📊 Top 5 Source Ports:")
    for port, count in source_ports.most_common(5):
        print(f"   Port {port}: {count} packets")

    print("\n📊 Top 5 Destination Ports:")
    for port, count in destination_ports.most_common(5):
        print(f"   Port {port}: {count} packets")

    #check for supisious activity
    for ip , port in ip_to_ports.items():
        if len(port) >= port_scan_limit:
            print(f"⚠️ Possible port scan detected from {ip} -> {len(port)} unique ports")

   # Convert defaultdict set to normal dict with list for JSON serialization,   including only suspicious IPs
    serialize_ip_to_port = {ip: list(port) for ip, port in ip_to_ports.items() if len(port) >= port_scan_limit}

    # --- Packet size statistics ---
    time_duration = end_time - start_time if start_time and end_time else 0 
    average_size = sum(packets_sizes) / len(packets_sizes) if packets_sizes else 0

    # Detect unusually large packets (heuristic: 3x average size)
    threshold_size = average_size * 3
    large_packets = [s for s in packets_sizes if s > threshold_size]
    print(f"\n📦 Large Packet Detection: {len(large_packets)} unusually large packets found "
          f"(> {threshold_size:.2f} bytes)")
    
    # --- Flood detection ---
    flood_ip = "None"
    for ip, times in ip_packet_times.items():
        times.sort()
        for i in range(len(times) - 100):
            if times[i + 100] - times[i] < 10:
                print(f"Possible flood from: {ip}")
                flood_ip = ip
                break
    print(f"DOS attack Reports:{dos_attack_happening}")
    print(f"DDOS attack Reports:{ddos_attack_happening}")
    print(f"SSH Brute Force attack Reports:{ssh_attack_happening}")
    print(f"SQL Injection Attack Report:{sql_injection_happening}")
    print(f"\n🚨 Flooding Detection (IPs with >100 packets in <10 seconds): {flood_ip}")
    print("Analysis Completed")
    
    # --- Store results in a dictionary ---
    results = {
        "Total Packets": packets_count,
        "Protocol Distribution": dict(protocols),
        "Service Distribution": dict(service_protocols),
        "top_source_ips": source_ip.most_common(5),
        "top_destination_ips": destination_ip.most_common(5),
        "top_source_ports": source_ports.most_common(5),
        "top_destination_ports": destination_ports.most_common(5),
        "capture_start": datetime.fromtimestamp(start_time).isoformat() if start_time else None,
        "capture_end": datetime.fromtimestamp(end_time).isoformat() if end_time else None,
        "duration_seconds": round(time_duration,1),
        "average_packet_size_bytes": round(average_size,1),
        "Large Packet Detection": len(large_packets),
        "Flooding Detection from": flood_ip,
        "Port scanning detection of": serialize_ip_to_port,
        "DOS Attack Report": dos_attack_happening,
        "DDOS Attack Report": ddos_attack_happening,
        "SSH Brute Force Attack Report":ssh_attack_happening,
        "SQL Injection Attack Report": sql_injection_happening
    }             

    # Save results in JSON format
    with open(analysis_file, 'w') as file:
        json.dump(results, file, indent=4)
    
    logging.info(f"Results saved to {analysis_file}")

    # --- Generate protocol distribution chart ---
    if chart and protocols:
        plt.figure(figsize=(8, 6))
        plt.pie(protocols.values(), labels=protocols.keys(), autopct='%1.1f%%')
        plt.title("Protocol Distribution")
        chart_file = get_unique_filename("data/Protocol_Distribution", ".png")
        plt.savefig(chart_file)
        plt.close()
        logging.info("Protocol distribution chart saved")
    
    get_ip_info(source_ip_info,"Source")
    get_ip_info(destination_ip_info,"Destination")
    
    return results
