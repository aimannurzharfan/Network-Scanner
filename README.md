# NetGuard: Network Vulnerability Scanner

## 1.0 Project Overview
NetGuard is a multi-threaded network reconnaissance tool developed in Python. It is designed to assist Network Administrators and Security Analysts in automating the identification of active network services. The tool performs rapid TCP port scanning, executes service banner grabbing to identify software versions, and aggregates findings into a structured PDF audit report.

## 2.0 Technical Features
* **Multi-Threaded Execution:** Utilizes Python's concurrent.futures module to manage a thread pool of 100 workers, allowing for rapid scanning of port ranges without significant latency.
* **Socket-Based Enumeration:** Implements raw socket connections to determine port states (Open/Closed/Filtered) based on TCP handshake responses.
* **Banner Grabbing:** Automatically attempts to retrieve the service header (first 1024 bytes) from active ports to aid in version detection.
* **Automated Reporting:** Generates a timestamped, non-editable PDF report containing scan metadata and a summary table of vulnerable points.
* **Error Handling:** Includes robust exception handling for network timeouts, socket errors, and user interruptions.

## 3.0 Installation

### 3.1 Prerequisites
* Python 3.10 or higher
* pip (Python Package Installer)

### 3.2 Setup Instructions
1.  Clone the repository to your local machine:
    ```bash
    git clone [https://github.com/your-username/NetGuard.git](https://github.com/your-username/NetGuard.git)
    cd NetGuard
    ```

2.  Install the required dependencies using the requirements file:
    ```bash
    pip install -r requirements.txt
    ```

## 4.0 Usage Guide

To execute a scan, run the script from the command line interface (CLI) with the target IP address as an argument.

**Command Syntax:**
```bash
python scanner.py <TARGET_IP_ADDRESS>
