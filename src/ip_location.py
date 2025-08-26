import requests
import json
import os
from datetime import datetime
import ipaddress

# File path for caching IP information
CACHE_FILE = "data/ip_information.json"

with open(CACHE_FILE,'w') as f:
    pass

def is_public_ip(ip):
    
    """
    Check if the given IP address is public (globally routable).
    Returns True if public, False otherwise.
    """
    
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        # Invalid IP address format
        return False


def load_cache(filename=CACHE_FILE):
    
    """
    Load existing cache from file.
    Returns a dictionary if data exists, otherwise empty dict.
    Handles corrupt/malformed JSON gracefully.
    """
    
    if os.path.exists(filename) and os.path.getsize(filename) > 0:
        try:
            with open(filename, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            print("[Warning] Cache file corrupted. Starting with empty cache.")
            return {}
    return {}


def save_cache(cache, filename=CACHE_FILE):
    
    """
    Save the cache dictionary to a JSON file.
    Uses indentation for readability.
    
    """
    try:
        with open(filename, "w") as f:
            json.dump(cache, f, indent=4)
    except Exception as e:
        print(f"[Error] Failed to save cache: {e}")


def get_ip_info(ip, which_ip):
    
    """
    Get IP information from ip-api.com.
    - First checks the local cache.
    - If not cached, makes a request.
    - Handles private IPs separately.
    - Returns a dictionary with IP details.
    """

    cache = load_cache()

    # Return from cache if available
    if ip in cache:
        return cache[ip]

    try:
       # print(f"[DEBUG] Checking IP: {ip}")  # Debug logging

        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
       # print(f"[DEBUG] Response Code: {response.status_code}")  # Debug logging

        # If API request was successful
        if response.status_code == 200:
            data = response.json()

            # Only process if IP is public
            if is_public_ip(ip):
                ip_info = {
                    "type": which_ip,
                    "ip": ip,  # ip-api uses 'query', not 'ip'
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "loc": f"{data.get('lat', 'Unknown')},{data.get('lon', 'Unknown')}",
                    "org": data.get("isp", "Unknown"),
                    "timezone": data.get("timezone", "Unknown"),
                    "first_seen": datetime.utcnow().isoformat() + "Z"
                }
                cache[ip] = ip_info
                save_cache(cache)
                return ip_info
            else:
                # Private IPs are not looked up via external API
                return {
                    "type": which_ip,
                    "ip": ip,
                    "info": "Private IP - no lookup",
                    "first_seen": datetime.utcnow().isoformat() + "Z"
                }

        else:
            return {"error": f"API returned status {response.status_code}"}

    except requests.exceptions.Timeout:
        return {"error": "Request timed out while fetching IP info"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Network request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

    return {"error": "Unknown response"}
