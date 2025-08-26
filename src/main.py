# main.py
# Entry point for Packet Sniffer & Traffic Analyzer Project

import os
from src.capture import capture_traffic
from src.analyzer import analyze_network_traffic
import pyfiglet


def print_banner():
    # Print a large ASCII art banner using pyfiglet
    ascii_banner = pyfiglet.figlet_format("\t\tNetwork Analyzer")
    print(ascii_banner)
    #print("\tTraffic Analyzer\n")


if __name__ == "__main__":
    print_banner()

    try:
        # === User Inputs ===
        number_of_packets = int(input("Enter the number of packets to capture: "))
        output_file_name = input("Enter the output file name (without extension): ").strip()
        analysis_file_name = input("Enter the analysis file name (without extension): ").strip()

        # === Directory Setup ===
        try:
            os.makedirs("log", exist_ok=True)   # Ensure log directory exists
            os.makedirs("data", exist_ok=True)  # Ensure data directory exists
        except Exception as dir_error:
            print(f"[Error] Could not create directories: {dir_error}")
            exit(1)

        # === File Paths ===
        output_file_path = os.path.join("log", f"{output_file_name}.pcap")
        print(f"[*] Output file will be saved as: {output_file_path}\n")

        analysis_file_path = os.path.join("data", f"{analysis_file_name}.json")

        # === Capture Traffic ===
        try:
            capture_traffic(number_of_packets, output_file_path)
        except Exception as cap_error:
            print(f"[Error] Failed during packet capture: {cap_error}")
            exit(1)

        # === Analyze Captured Traffic ===
        try:
            traffic_analysis = analyze_network_traffic(output_file_path, analysis_file_path, chart=True)
            print("[*] Traffic analysis completed successfully.")
        except Exception as ana_error:
            print(f"[Error] Failed during traffic analysis: {ana_error}")

    except ValueError:
        print("[Error] Please enter a valid integer for packet count.")
    except KeyboardInterrupt:
        print("\n[!] Process interrupted by user.")
    except Exception as e:
        print(f"[Error] Unexpected issue: {e}")
