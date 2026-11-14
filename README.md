# NetGuard: Network Port Scanner

A multi-threaded TCP port scanner in Python. It finds open ports on a host, grabs each service's banner to identify the software and version, and writes the results to a PDF audit report.

NetGuard was my first security tool. It later grew into [NetGuard Sentinel](https://github.com/aimannurzharfan/Netguard-Sentinel), which takes the scan further by matching services to known CVEs and ranking them by real-world exploitability.

[Watch the demo on YouTube](https://youtu.be/vQmuTjyilvs)

## Features

- **Fast scanning.** A pool of worker threads (`concurrent.futures`, 100 by default) scans ports in parallel.
- **Port state detection.** TCP connect attempts classify each port as open, closed or filtered.
- **Banner grabbing.** Reads the first 1,024 bytes a service sends back, which usually reveals the software and version.
- **PDF report.** A timestamped report with scan details and a table of open ports and banners.
- **Clean failure handling.** Timeouts, socket errors and Ctrl+C are handled without crashing.

## Requirements

- Python 3.10 or newer
- pip

## Setup

```bash
git clone https://github.com/aimannurzharfan/Network-Scanner.git
cd Network-Scanner
pip install -r requirements.txt
```

On Windows PowerShell you can use the setup script instead, which creates a virtual environment and installs everything:

```powershell
.\setup_env.ps1
.\.venv\Scripts\Activate.ps1
```

## Usage

```bash
python scanner.py <target>                   # common ports
python scanner.py 127.0.0.1 -p 1-1024        # a range
python scanner.py 127.0.0.1 -p 22,80,443     # a list
python scanner.py 127.0.0.1 -p all -w 200    # all 65,535 ports, 200 threads
```

The target can be an IP address or a hostname. The report is saved as `netguard_last_scan.pdf` and is overwritten on each run. A recorded walkthrough is also included as `demo.mp4`.

## Legal and responsible use

Only scan systems you own or have written permission to test. Unauthorised scanning can break the law, including Malaysia's Computer Crimes Act 1997 and similar laws in other countries. This tool is for learning and authorised audits only, and the author is not responsible for misuse.
