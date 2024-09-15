Automated Penetration Testing Script

This repository contains a Python-based Automated Penetration Testing Script that streamlines the process of scanning, vulnerability assessment, and optional exploitation on a given target. It integrates powerful security tools like Nmap, Nikto, and Metasploit to automate the process of reconnaissance and penetration testing.

 Features:
- Target Discovery: Automatically scan all ports of the target system using Nmap and generate a detailed report of open ports and running services.
- Vulnerability Scanning: Perform web vulnerability scanning using Nikto to detect common security issues.
- Exploitation (Optional): Use Metasploit to attempt exploitation of discovered vulnerabilities (enabled with the `--exploit` flag).
- Multi-threading: Scans run concurrently for faster execution using multi-threading.
- Report Generation: Generates structured reports in either plain text or JSON format, making it easy to review or automate further actions.
  
 Technologies Used:
- Python: Core programming language for scripting.
- Nmap: Network discovery and port scanning.
- Nikto: Web vulnerability scanner.
- Metasploit: Framework for exploitation.
- Threading: For running scans in parallel.

 Usage:
bash
python pentest_script.py -t <target_ip_or_domain> -f <report_format> --exploit


- `-t` or `--target`: Specify the target IP or domain.
- `-f` or `--format`: Choose the report format, either `txt` (default) or `json`.
- `-e` or `--exploit`: Optional flag to enable exploitation after scanning.

 Example:
bash
python pentest_script.py -t 192.168.1.10 -f json --exploit


 Installation:
1. Clone the repository:
   bash
   git clone https://github.com/omjadhav25/TestPen
   
2. Install the required dependencies:
   bash
   pip install -r requirements.txt
   
3. Ensure that Nmap, Nikto, and Metasploit are installed on your system.

 Disclaimer:
This tool is intended for educational purposes and ethical hacking only. Unauthorized use of this script against systems without permission is illegal.

---

# TestPen
# TestPen
