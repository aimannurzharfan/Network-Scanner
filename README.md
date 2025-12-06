# NetGuard - Network Scanner

A comprehensive command-line network port scanner with banner grabbing and PDF reporting capabilities.

## ⚠️ Legal Disclaimer

**NetGuard is intended for educational purposes and authorized security audits only.** Scanning networks without permission is illegal and a violation of the Computer Fraud and Abuse Act (CFAA). The author is not responsible for any misuse of this tool. Always ensure you have explicit permission before scanning a target.

## Features

- 🔍 Scans top 50 common ports
- ⚡ Multi-threaded scanning for fast results
- 🎯 Banner grabbing to identify running services
- 📄 PDF report generation
- 🎨 Color-coded terminal output (hacker-style)
- ⌨️ Graceful KeyboardInterrupt handling (Ctrl+C)

## Installation

1. Clone or download this repository
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py <target_ip>
```

### Example

```bash
python scanner.py 192.168.1.1
```

## Output

- **Terminal**: Real-time colored output showing open ports and banners
- **PDF Report**: Automatically generated `netguard_scan_report.pdf` containing:
  - Target IP address
  - Scan start/end times
  - Table of open ports with banners

## How It Works

The scanner uses:
- **Socket Library**: Creates TCP connections to test port availability
- **Multi-threading**: Concurrent port scanning using ThreadPoolExecutor
- **Banner Grabbing**: Receives service identification data from open ports
- **PDF Generation**: Creates professional scan reports using fpdf2

## Ports Scanned

The scanner checks 50 common ports including:
- Web servers (80, 443, 8080, 8443)
- SSH/Telnet (22, 23)
- Database servers (3306, 5432, 27017)
- Email servers (25, 110, 143, 993, 995)
- And many more...

## Requirements

- Python 3.6+
- fpdf2
- colorama

## Notes

- The scanner uses a 1-second timeout per port to balance speed and accuracy
- Maximum 100 concurrent threads (adjustable in code)
- Partial scans (interrupted with Ctrl+C) generate a partial report if ports were found
