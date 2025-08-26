import socket #used for identification of ports
import os
import json
from datetime import datetime
import time

attack_file_name = "data/attacks.json"

# Mapping of protocol numbers to human-readable names
PROTOCOLS_MAPPING = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
    2: "IGMP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
}

# Mapping of common port numbers to application-layer services
SERVICE_PROTOCOLS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMPTRAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP (Submission)",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1433: "MSSQL",
    1521: "Oracle DB",
    1723: "PPTP",
    1812: "RADIUS Auth",
    1813: "RADIUS Acct",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel SSL",
    2222: "Alternate SSH",
    2375: "Docker API",
    2483: "Oracle DB",
    2484: "Oracle DB SSL",
    3128: "Proxy",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4444: "Metasploit/Backdoor",
    5060: "SIP",
    5061: "SIP-TLS",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9000: "SonarQube",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


def get_service_name(port):
    """Return the service name for a given port number."""
    try:
        # Check custom mapping first
        if port in SERVICE_PROTOCOLS:
            return SERVICE_PROTOCOLS[port]
        # Fall back to Python's socket library
        return socket.getservbyport(port)
    except:
        return "unknown"
        


def get_unique_filename(base_name, extension):
    """
    Generate a unique filename by appending a number if the file already exists.

    Args:
        base_name (str): Base name of the file without extension.
        extension (str): File extension including the dot.

    Returns:
        str: A unique filename with the extension.
    """
    counter = 0
    while True:
        if counter == 0:
            filename = f"{base_name}{extension}"
        else:
            filename = f"{base_name}_{counter}{extension}"
        if not os.path.exists(filename):
            return filename
        counter += 1


def log_attack_to_json(attack_type, source_ip, destination_port, details):
    
    

    """Logs detected attack details into a JSON file"""
    
    log_entry = {
        "attack_type": attack_type,
        "source_ip": source_ip,
        "destination_port": destination_port,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "details": details
    }
    
    try:
        #load existing data
        with open(attack_file_name,'r') as f:
            logs = json.load(f)
    
    except (FileNotFoundError,json.JSONDecodeError):
        logs = []
    
    logs.append(log_entry)
    
    #save back to file
    with open(attack_file_name,'w') as f:
        json.dump(logs,f,indent=4)
 