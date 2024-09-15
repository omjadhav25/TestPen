import subprocess
import nmap
import os
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Step 1: Target Discovery (Nmap Scan)
def scan_target(target):
    try:
        print(f"[*] Scanning target {target} with Nmap...")
        scanner = nmap.PortScanner()
        scan_result = scanner.scan(target, '1-65535')  # Scan all ports
        return scan_result
    except Exception as e:
        print(f"[!] Error during Nmap scan: {e}")
        return None

# Step 2: Vulnerability Scanning (Nikto)
def nikto_scan(target):
    try:
        print(f"[*] Running Nikto on {target}...")
        nikto_command = f"nikto -h {target} -output nikto_report.txt"
        os.system(nikto_command)
        print("[+] Nikto scan completed. Report saved as 'nikto_report.txt'.")
    except Exception as e:
        print(f"[!] Error during Nikto scan: {e}")

# Step 3: Exploitation (Using Metasploit)
def exploit_vulnerabilities():
    try:
        print("[*] Attempting exploitation using Metasploit...")
        # Customize the module and payload depending on detected vulnerabilities
        os.system("msfconsole -q -x 'use exploit/multi/handler; run;'")
    except Exception as e:
        print(f"[!] Error during exploitation: {e}")

# Step 4: Report Generation
def generate_report(scan_result, report_format="txt"):
    print("[*] Generating report...")
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f'report_{timestamp}.{report_format}'
    
    try:
        if report_format == "txt":
            with open(filename, 'w') as report_file:
                for host in scan_result['scan']:
                    report_file.write(f"Host: {host}\n")
                    report_file.write(f"State: {scan_result['scan'][host]['status']['state']}\n")
                    for protocol in scan_result['scan'][host].get('tcp', {}):
                        port = scan_result['scan'][host]['tcp'][protocol]
                        report_file.write(f"Port: {protocol} | State: {port['state']} | Service: {port.get('name', 'unknown')}\n")
        elif report_format == "json":
            with open(filename, 'w') as report_file:
                json.dump(scan_result, report_file, indent=4)
        print(f"[+] Report saved as {filename}")
    except Exception as e:
        print(f"[!] Error generating report: {e}")

# Main function with user inputs and improved flexibility
def main():
    # Argument parser for CLI input
    parser = argparse.ArgumentParser(description="Automated Penetration Testing Tool")
    parser.add_argument('-t', '--target', required=True, help="Target IP address or domain")
    parser.add_argument('-f', '--format', default="txt", choices=['txt', 'json'], help="Report format (txt or json)")
    parser.add_argument('-e', '--exploit', action='store_true', help="Attempt to exploit vulnerabilities after scanning")
    args = parser.parse_args()

    target_ip = args.target
    report_format = args.format

    # Run tasks in parallel (Nmap Scan and Nikto Scan)
    with ThreadPoolExecutor(max_workers=2) as executor:
        nmap_future = executor.submit(scan_target, target_ip)
        nikto_future = executor.submit(nikto_scan, target_ip)

        # Get scan results from the Nmap scan
        scan_result = nmap_future.result()

    if scan_result:
        # Generate report based on the Nmap results
        generate_report(scan_result, report_format)

    # Optionally run Metasploit exploitation
    if args.exploit:
        exploit_vulnerabilities()

if __name__ == "__main__":
    main()
