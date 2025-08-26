# capture.py
# Handles capturing network traffic

from scapy.all import sniff, wrpcap
import os
from scapy.error import Scapy_Exception

def capture_traffic(packet_count, output_file, timeout=60):
    
    """
    Capture incoming and outgoing network traffic and save to a PCAP file.

    Args:
        packet_count (int): Number of packets to capture.
        output_file (str): Path to save the captured packets (.pcap).
        timeout (int): Max time (seconds) to wait for packets. Default = 60.
    """

    try:
        # --- Input validation ---
        if not isinstance(packet_count, int) or packet_count <= 0:
            raise ValueError("Packet count must be a positive integer.")

        # Validate output directory permissions
        output_dir = os.path.dirname(output_file) or "."
        if not os.access(output_dir, os.W_OK):
            raise OSError(f"Write access restricted to {output_dir}")

        print(f"[*] Starting capture: {packet_count} packets (timeout={timeout}s)")

        # --- Packet capture process ---
        packets = sniff(count=packet_count, timeout=timeout)

        if not packets:
            print("[!] No packets captured. Check network activity or connectivity.")
            return

        # --- Save captured packets ---
        wrpcap(output_file, packets)
        print(f"[+] Capture complete. Saved {len(packets)} packets to {output_file}")
    
    # --- Error handling ---
    except PermissionError as e:
        print(f"[Error] Run as administrator (Windows) or with sudo (Linux): {e}")
    except ValueError as e:
        print(f"[Error] Invalid input: {e}")
    except OSError as e:
        print(f"[Error] File operation failed: {e}")
    except Scapy_Exception as e:
        print(f"[Error] Scapy library error: {e}")
    except Exception as e:
        print(f"[Error] Unexpected issue: {e}")
