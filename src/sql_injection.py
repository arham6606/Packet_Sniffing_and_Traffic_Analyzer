import re
import json
from src.discord_alert import send_discord_alert

def Detect_SQL_Injection(payload,src_ip,dest_ip,time,dport):
    
    '''
        Detects potential SQL injection attempts in both HTTP and direct DB traffic 
    '''

    suspicious_patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",              # SQL comment / quote
        r"(\bOR\b|\bAND\b)\s+\d+=\d+",                 # Logical OR/AND abuse
        r"UNION(\s+ALL)?\s+SELECT",                    # UNION SELECT injection
        r"(?i)information_schema",                     # Information schema
        r"(?i)xp_cmdshell",                            # SQL Server abuse
        r"(\%3D)|(=)",                                 # Encoded equal signs
        r"(?i)insert\s+into",                          # SQL injection via insert
        r"(?i)drop\s+table",                           # DROP table injection
        r"(?i)update\s+\w+\s+set",                     # Update abuse
    ]

    for pattern  in suspicious_patterns:
        if re.search(pattern,payload,re.IGNORECASE):
            
            detection = f"[!] SQL Injection attempt detected from {src_ip} targeting {dest_ip}:{dport} at {time}"

            try:
                with open("data/attacks.json", "r") as f:
                 data = json.load(f)
            
            except FileNotFoundError:
                data = []

            data.append(detection)

            with open("data/attacks.json", "w") as f:
                json.dump(data, f, indent=4)

            #send discord alerts
            send_discord_alert(
                "SQL Injection Attempted",
                f"Detected from:{src_ip}"
            )

    
            
            return f"[!] SQL Injection attempt detected"
    
    return "None"