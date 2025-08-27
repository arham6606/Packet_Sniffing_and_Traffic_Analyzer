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


def get_ip_info(ips, which_ip):
    
    """
    Get IP information from ip-api.com.
    - Accepts a single IP (string) or list of IPs.
    - Uses cache to avoid duplicate lookups.
    - Handles private IPs separately.
    - Returns a dict (for single IP) or list of dicts (for multiple IPs).
    """

    cache = load_cache()

    # Normalize to list
    if isinstance(ips, str):
        ips = [ips]

    results = []
    for ip in ips:
        if ip in cache:
            results.append(cache[ip])
            continue

        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)

            if response.status_code == 200:
                data = response.json()

                if is_public_ip(ip):
                    ip_info = {
                        "type": which_ip,
                        "ip": ip,
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
                    results.append(ip_info)
                else:
                    results.append({
                        "type": which_ip,
                        "ip": ip,
                        "info": "Private IP - no lookup",
                        "first_seen": datetime.utcnow().isoformat() + "Z"
                    })
            else:
                results.append({"ip": ip, "error": f"API returned status {response.status_code}"})

        except requests.exceptions.Timeout:
            results.append({"ip": ip, "error": "Request timed out while fetching IP info"})
        except requests.exceptions.RequestException as e:
            results.append({"ip": ip, "error": f"Network request failed: {str(e)}"})
        except Exception as e:
            results.append({"ip": ip, "error": f"Unexpected error: {str(e)}"})

    # Return a single dict if input was one IP, else list
    return results[0] if len(results) == 1 else results