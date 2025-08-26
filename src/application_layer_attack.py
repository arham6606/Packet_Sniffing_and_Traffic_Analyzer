from collections import defaultdict
from src.analyzer_helper import log_attack_to_json
from src.discord_alert import send_discord_alert
from src.analyzer_helper import attack_file_name

#this is used to store time at which the IP is coming
http_dos_attack = defaultdict(list)
http_ddos_attack = defaultdict(list)
ssh_brute_force = defaultdict(list)

counter_ssh = 1
counter_ddos = 1 
counter_dos = 1

#clear attack_json file every time the program runs
with open(attack_file_name,'w') as f:
    pass

def Detect_DOS_Attack(destination_port,source_ip,current_time):

    '''this function is used to detect the DDOS attack'''
     
    global counter_dos

    if destination_port in [80,443]:
        http_dos_attack[source_ip].append(current_time)
        
        recent_http = [time for time in http_dos_attack[source_ip] if current_time - time < 10]
        if len(recent_http) >= 100:
            if counter_dos <= 2:
                log_attack_to_json(
                "DOS Attack",source_ip,destination_port,{"Sends Packets in Last 10s":len(recent_http)}
                )

                send_discord_alert(
                    "DOS Attack Detected",
                    f"HTTP Flood suspected from {source_ip}",
                    {"Packets (last 10's)":len(recent_http),"Target Port":destination_port}
                )

                counter_dos+=1

            return (f"⚠️ HTTP Flood suspected from {source_ip}")
    
    return "None"



def Detect_DDOS_Attack(destination_port,source_ip,current_time):

    '''
    Detects potential DDOS attacks which comes from mulitple IPS and they targets the port 80 and 443
    '''

    global counter_ddos
   

    #the DDOS attack only focus is on web servers
    if destination_port in [80,443]:
        http_ddos_attack[destination_port].append((source_ip,current_time))

        #filer packets
        recent_http = [(ip , time) for ip , time in http_ddos_attack[destination_port] if current_time - time < 10 ]

        # get unique ip's
        unique_ip = set(ip for ip, _ in recent_http)
        
        if len(unique_ip) >=20 and len(recent_http) >=200:
            if counter_ddos <=2:
                log_attack_to_json(
                
                    "DDOS Attack",
                    list(unique_ip),
                    destination_port,
                    {"Unique IP":len(unique_ip),"Total requests in last 10s":len(recent_http)}
                )

                send_discord_alert(
                    "DDOS Attack Detected",
                    "Multiple IP's Attacking",
                    {"Packet (Last 10's)":len(recent_http),"Target Port":destination_port}
                )
                
                counter_ddos+=1

            return f"⚠️ DDoS suspected on port {destination_port} from {len(unique_ip)} unique IPs"

    return "None"


def Detect_SSH_Brute_Force(destination_port,source_ip,current_time):

    '''
    Detects SSH brute force attempts based on multiple failed connection attempts 
    from the same IP within a short time window.
    '''

    global counter_ssh    

    #check only SSH port 
    if destination_port == 22:
        ssh_brute_force[source_ip].append(current_time)

        #keep the record of last 60 seconds
        recent_attempts = [time for time in ssh_brute_force[source_ip] if current_time - time < 60]

        #if one ip tries to log more than 10 time SSH brute forcing detect
        if len(recent_attempts)>=10:
            if counter_ssh <=2:
                log_attack_to_json(
                
                    "SSH Brute Force Attack",
                    source_ip,
                    destination_port,
                    {"Failed attempt in Last 60s": len(recent_attempts)}
                )

                send_discord_alert(
                    "SSH Brute Force Attempt",
                    f"Mulitple Failed Login from {source_ip}",
                    {"Attempts (Last 60's)": len(recent_attempts)}
                )
                counter_ssh+=1

            return f"⚠️ SSH Brute Force suspected from {source_ip} ({len(recent_attempts)} attempts in last 60s)"
    
    return "None"


