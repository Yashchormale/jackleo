
JACKLEO v4.3
Port Scanner, Service Fingerprinter & Metasploit Module Advisor
JACKLEO is a Python-based network reconnaissance and security-assessment tool designed for authorized lab environments and systems you have permission to test. It scans TCP ports, fingerprints exposed services, checks selected product/version strings against a small built-in CVE signature table, and can discover relevant Metasploit module names for further manual investigation.
> \*\*Safety notice:\*\* Use JACKLEO only on systems you own or are explicitly authorized to assess. The optional auxiliary checks interact with services to test for common misconfigurations. JACKLEO does not execute Metasploit exploit modules.
Features
TCP port scanning — scans a default list of common ports or all 65,535 TCP ports.
Flexible targets — accepts a single IP address, hostname, or CIDR range, subject to the tool's host limit.
Service fingerprinting — reads service banners and parses product/version information for supported protocols.
CVE signature matching — checks selected detected product/version combinations against a small built-in signature table and reports severity and remediation guidance.
Nmap integration — can run Nmap service detection and vulnerability/NSE script checks against discovered open ports.
Metasploit module discovery — searches the local Metasploit module database and filters candidate auxiliary/exploit module paths for relevance. These are recommendations only; a match does not confirm that a target is vulnerable.
Optional auxiliary checks — checks for selected configurations such as anonymous FTP, unauthenticated Redis, Memcached, MongoDB, Elasticsearch, and VNC “None” authentication.
Heuristic OS hint — provides a rough TTL-based operating-system guess; treat it as an estimate, not a confirmed identification.
HTML reports — generates a browser-viewable report of scan results.
JSON reports — can save structured results in JSON format.
Terminal output — prints a readable summary directly in the command line.
Readable output — uses Rich for a colored table when installed, with a plain-text fallback.
How it works
Resolve the target IP address or expand the supplied CIDR range.
Scan the selected TCP ports using concurrent connections.
Read available service banners and identify likely service/product versions.
Match supported product/version strings against the built-in CVE signatures.
Optionally run Nmap checks and auxiliary misconfiguration checks.
Search for relevant Metasploit module names where Metasploit is installed.
Display the findings and generate the HTML report; optionally export a JSON report.
Requirements
Python 3.8 or later
Nmap, for Nmap service detection and NSE integrations
Metasploit Framework / `msfconsole`, for module discovery
Optional Python package: `rich`
The basic scanner can fall back to plain-text output if `rich` is not installed. Nmap and Metasploit-related features require their respective command-line tools to be installed and available in `PATH`.
Installation
1. Clone the repository
```bash
git clone https://github.com/Yashchormale/jackleo.git
cd jackleo
```
Replace the placeholders with your actual repository URL and directory name.
2. (Optional) Create a virtual environment
```bash
python3 -m venv .venv
```
Linux/macOS:
```bash
source .venv/bin/activate
```
Windows PowerShell:
```powershell
.venv\\Scripts\\Activate.ps1
```
3. Install the optional Rich dependency
```bash
python3 -m pip install rich
```
4. Verify external tools
```bash
nmap --version
msfconsole --version
```
Install Nmap and Metasploit Framework using the official instructions for your operating system if they are not already installed. The core scanner can run without these integrations, but the corresponding features will be unavailable.
Usage
Run the script from the project directory. If your source file is named `portscan.py`, use the commands below.
Scan common TCP ports
```bash
python3 portscan.py <target>
```
Example using an isolated lab VM:
```bash
python3 portscan.py 192.168.56.101
```
Use the actual IP address assigned to your own Metasploitable 2 VM.
Scan all TCP ports
```bash
python3 portscan.py <target> --full
```
Enable optional auxiliary checks
```bash
python3 portscan.py <target> --aux-scan
```
Only use this option on systems you are authorized to test. These checks send protocol requests and may attempt a limited anonymous FTP login; they are not merely passive banner collection.
Scan a CIDR range
```bash
python3 portscan.py 192.168.56.0/28 --threads 300
```
The script applies its built-in host expansion limit. Keep scans scoped to your authorized lab network.
Save a JSON report
```bash
python3 portscan.py <target> --json scan\_report.json
```
HTML report
JACKLEO also generates an HTML report for reviewing scan findings in a web browser. The report may include target and scan details, detected ports and services, CVE/signature matches, remediation notes, Nmap findings, Metasploit module candidates, and auxiliary-check results, depending on which checks were enabled and what the target returned.
The exact HTML-report command or option is not documented here because it was not identifiable from the provided source excerpt. Check the script's `--help` output or the HTML-report generation code for the exact invocation; do not assume a flag name.
Enable verbose diagnostics
```bash
python3 portscan.py <target> -v
```
> Use `python` instead of `python3` on systems where that is the correct Python command. Check `python3 portscan.py --help` for the exact options supported by your local copy.
Metasploitable 2 lab
JACKLEO can be used in an isolated lab to practice network reconnaissance against Metasploitable 2, an intentionally vulnerable training VM.
Suggested workflow:
Run Kali Linux and Metasploitable 2 in a host-only or otherwise isolated virtual network.
Confirm the target VM's IP address from the VM console.
Start with a common-port scan.
Review open ports, service banners, version information, and any CVE signature matches.
If authorized for the lab, use `--aux-scan` to run the supported auxiliary checks.
Review any suggested Metasploit module names manually and verify relevance against reliable vendor advisories and lab documentation.
Save a JSON report for notes and portfolio evidence.
Do not expose intentionally vulnerable VMs to the public internet. Do not treat a detected version or suggested module as proof of exploitability.
HTML and JSON reports
JACKLEO generates an HTML report that you can open in a web browser to review scan findings. Depending on the features enabled and the results returned, the report may include target and scan details, discovered ports and services, product/version information, CVE matches, severity and remediation guidance, Nmap findings, Metasploit module candidates, auxiliary-check results, and scan diagnostics.
To request a JSON report as well, use the command-line option shown below (assuming your script supports the documented `--json` option):
```bash
python3 portscan.py <target> --json scan\_report.json
```
The HTML report's exact filename and output location depend on the implementation and the options used. Check the terminal output or your script's help text to find the generated report.
Interpret results carefully: version-based CVE matches and Metasploit module suggestions are leads for manual validation, not proof that a target is exploitable.
Output and interpretation
The terminal output and generated reports may include:
Port number and state
Service name
Product/version or banner information
CVE/signature matches and severity
Remediation notes
Metasploit module candidates
Optional auxiliary-check findings
An approximate OS hint
HTML report for browser-based review, when generated by the script
JSON report output location, when requested
Important limitations
The built-in CVE table is small and manually defined, not a complete or continuously updated vulnerability database.
Version-based matching can produce false positives or miss vulnerabilities when banners are absent, misleading, patched, or backported.
Nmap script results require manual validation; confirm findings against vendor advisories and other trusted sources.
Metasploit module discovery returns candidate module paths only. It does not run exploit modules and does not establish that a host is exploitable.
The TTL-based OS guess is heuristic.
Results depend on network reachability, firewall behavior, installed external tools, and service responses.
Auxiliary checks make real protocol interactions and should only be used with explicit authorization.
Example project structure
```text
JACKLEO/
├── portscan.py
├── README.md
└── scan\_report.json       # optional generated report; review before sharing
```
Adjust this example to match the actual files in your repository. Do not commit private scan results, credentials, API keys, or data from systems you do not have permission to disclose.
Responsible use
JACKLEO is intended for learning, defensive assessment, and authorized security testing. You are responsible for obtaining permission, following applicable laws and policies, and limiting scans to approved targets. Do not use the tool to access, disrupt, exploit, or modify systems without authorization.
Disclaimer
This project is provided for educational and authorized security-testing purposes. It is supplied “as is,” without warranty. Findings are indicators for further investigation, not a substitute for a full professional security assessment.
