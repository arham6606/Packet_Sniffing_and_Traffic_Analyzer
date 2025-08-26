from collections import defaultdict
import time
from src.application_layer_attack import Detect_DDOS_Attack,Detect_DOS_Attack,Detect_SSH_Brute_Force
from src.sql_injection import Detect_SQL_Injection
# global storages for detection
http_dos_attack = defaultdict(list)
http_ddos_attack = defaultdict(list)

# paste your functions here ...


# ---------- Test DOS ----------
print("Testing DoS Detection...")
for i in range(105):  # simulate 105 requests from the same IP in <10 seconds
    result = Detect_DOS_Attack(80, "192.168.1.10", time.time())
    if result != "None":
        print(result)

# ------------------ Test ------------------
print("Testing DDoS Detection...\n")

# generate 25 unique IPs
ips = [f"192.168.1.{i}" for i in range(1, 26)]

# send 250 requests within 10 seconds
for i in range(250):
    ip = ips[i % len(ips)]   # cycle through unique IPs
    result = Detect_DDOS_Attack(80, ip, time.time())
    if result != "None":
        print(result)



# ----------- Manual Test --------------
print("Testing SSH Brute Force Detection...\n")

for i in range(1, 15):  
    result = Detect_SSH_Brute_Force(22, "192.168.1.5", i*5)  # attempt every 5 seconds
    print(f"Attempt {i} at time {i*5}s -> {result}")


#------------testing sql injection--------------------
print("Testing SQL Injection......")
# Sample test payloads
test_cases = [
    {
        "payload": "username=admin' OR '1'='1; --",
        "src_ip": "192.168.1.10",
        "dest_ip": "10.0.0.5",
        "time": "2025-08-26 14:32:10",
        "dport": 3306
    },
    {
        "payload": "SELECT * FROM users WHERE id=1",
        "src_ip": "192.168.1.15",
        "dest_ip": "10.0.0.5",
        "time": "2025-08-26 14:32:15",
        "dport": 80
    },
    {
        "payload": "DROP TABLE accounts;",
        "src_ip": "192.168.1.20",
        "dest_ip": "10.0.0.5",
        "time": "2025-08-26 14:32:20",
        "dport": 1433
    },
    {
        "payload": "normal harmless request",
        "src_ip": "192.168.1.25",
        "dest_ip": "10.0.0.5",
        "time": "2025-08-26 14:32:25",
        "dport": 80
    },
]

# Run tests
for case in test_cases:
    result = Detect_SQL_Injection(
        case["payload"],
        case["src_ip"],
        case["dest_ip"],
        case["time"],
        case["dport"]
    )
    print(f"Payload: {case['payload']}\nResult: {result}\n{'-'*60}")