#!/usr/bin/env python3
"""
NetGuard - Network Scanner Tool
A comprehensive network port scanner with banner grabbing and PDF reporting.
For educational purposes and authorized security audits only.
"""

import argparse
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from fpdf import FPDF, XPos, YPos
from colorama import init, Fore, Style

# Initialize colorama for Windows compatibility
init(autoreset=True)

# Port Scanner
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 27017, 5432, 1521, 1433,
    5000, 5060, 8000, 8001, 8008, 8010, 8081, 8090, 8880, 9001, 9090, 9200,
    27015, 25565, 22, 23, 25, 53, 80, 443, 3306, 8080
]

# Remove duplicates and sort
COMMON_PORTS = sorted(list(set(COMMON_PORTS)))


def parse_ports(spec):
    """Turn a --ports value into a sorted list of ints.
    Accepts: 'common', 'all', a range like '1-65535', or a CSV like '22,80,443'."""
    if spec in (None, '', 'common'):
        return COMMON_PORTS
    if spec == 'all':
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(','):
        part = part.strip()
        if '-' in part:
            lo, hi = part.split('-', 1)
            ports.update(range(int(lo), int(hi) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def resolve_target(target):
    """Accept an IP or a hostname; return a usable IPv4 address or exit."""
    try:
        return socket.gethostbyname(target)
    except socket.error:
        print(f"{Fore.RED}[-] Could not resolve target: {target}{Style.RESET_ALL}")
        sys.exit(1)

# Global variables for results and synchronization
open_ports = []
lock = threading.Lock()
start_time = None
target_ip = None


class PDFReport(FPDF):
    """Custom PDF class for generating network scan reports"""
    
    def header(self):
        """PDF header with title"""
        self.set_font('Helvetica', 'B', 16)
        self.cell(0, 10, 'NetGuard Network Scan Report', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        self.ln(5)
    
    def footer(self):
        """PDF footer with page number"""
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', border=0, new_x=XPos.RIGHT, new_y=YPos.TOP, align='C')


def scan_port(ip, port, timeout=1.0):
    """
    Scan a single port on the target IP address.
    
    Socket Connection Logic:
    1. Create a socket object using socket.socket() - this creates an endpoint for communication
    2. Set socket timeout to prevent hanging on closed/filtered ports
    3. Use socket.connect_ex() instead of connect() - it returns an error code instead of raising exception
    4. If connection succeeds (returns 0), the port is open
    5. Attempt to grab banner by receiving data from the socket
    6. Close the socket connection properly to free resources
    
    Args:
        ip (str): Target IP address
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds
    
    Returns:
        tuple: (port, status, banner) where status is 'open' or 'closed'
    """
    try:
        # Create a socket object
        # AF_INET = IPv4 address family
        # SOCK_STREAM = TCP protocol (connection-oriented)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set socket timeout to prevent hanging
        # This ensures the scan doesn't wait indefinitely for a response
        sock.settimeout(timeout)
        
        # Attempt to connect to the target IP and port
        # connect_ex() returns 0 on success, error code on failure
        # This is preferred over connect() because it doesn't raise exceptions
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            # Port is open - connection successful
            banner = grab_banner(sock)
            sock.close()
            return (port, 'open', banner)
        else:
            # Port is closed or filtered - connection failed
            sock.close()
            return (port, 'closed', None)
            
    except socket.timeout:
        # Timeout occurred - port is likely filtered or host is down
        return (port, 'timeout', None)
    except socket.error as e:
        # Socket error occurred (e.g., network unreachable)
        return (port, 'error', None)
    except Exception as e:
        # Unexpected error
        return (port, 'error', None)


def grab_banner(sock, buffer_size=1024):
    """
    Attempt to grab the service banner from an open port.
    
    Banner Grabbing Logic:
    1. After a successful connection, many services send a welcome message
    2. Use socket.recv() to receive data from the socket
    3. Set a short timeout for receiving to avoid hanging
    4. Decode the received bytes to a string
    5. Clean and return the banner (first 1024 bytes typically contains service info)
    
    Args:
        sock (socket): Connected socket object
        buffer_size (int): Maximum bytes to receive
    
    Returns:
        str: Banner string or None if no banner received
    """
    try:
        # Set a short timeout for receiving data
        sock.settimeout(0.5)
        
        # Attempt to receive data from the socket
        # recv() returns bytes, so we need to decode it
        banner = sock.recv(buffer_size)
        
        if banner:
            # Decode bytes to string and clean it up
            # Strip whitespace and replace newlines with spaces for readability
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            banner_str = banner_str.replace('\n', ' ').replace('\r', ' ')
            # Limit banner length for display
            return banner_str[:200] if len(banner_str) > 200 else banner_str
        else:
            return None
            
    except socket.timeout:
        # No banner received within timeout
        return None
    except Exception as e:
        # Error receiving banner
        return None


def print_result(port, status, banner=None):
    """
    Print scan results with colorama colors.
    
    Args:
        port (int): Port number
        status (str): Port status
        banner (str): Banner information if available
    """
    if status == 'open':
        print(f"{Fore.GREEN}[+] Port {port} is OPEN{Style.RESET_ALL}", end='')
        if banner:
            print(f" - Banner: {banner}")
        else:
            print(" - No banner received")
    elif status == 'error':
        print(f"{Fore.RED}[-] Port {port} - Error occurred{Style.RESET_ALL}")


def generate_pdf_report(target_ip, start_time, open_ports_data, total_scanned=len(COMMON_PORTS), filename='netguard_last_scan.pdf'):
    """
    Generate a PDF report of the scan results.
    
    Args:
        target_ip (str): Target IP address
        start_time (datetime): Scan start time
        open_ports_data (list): List of tuples (port, banner)
        filename (str): Output PDF filename
    """
    try:
        pdf = PDFReport()
        pdf.add_page()
        
        # Report metadata
        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(0, 10, 'Scan Information', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
        pdf.set_font('Helvetica', '', 10)
        pdf.cell(0, 8, f'Target IP: {target_ip}', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
        pdf.cell(0, 8, f'Start Time: {start_time.strftime("%Y-%m-%d %H:%M:%S")}', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
        pdf.cell(0, 8, f'End Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
        pdf.cell(0, 8, f'Total Ports Scanned: {total_scanned}', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
        pdf.cell(0, 8, f'Open Ports Found: {len(open_ports_data)}', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
        pdf.ln(10)
        
        # Open ports table
        if open_ports_data:
            pdf.set_font('Helvetica', 'B', 12)
            pdf.cell(0, 10, 'Open Ports and Banners', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
            pdf.ln(5)
            
            # Table header
            pdf.set_font('Helvetica', 'B', 10)
            pdf.cell(30, 8, 'Port', border=1, new_x=XPos.RIGHT, new_y=YPos.TOP, align='C')
            pdf.cell(160, 8, 'Banner/Service', border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
            
            # Table rows
            pdf.set_font('Helvetica', '', 9)
            for port, banner in open_ports_data:
                pdf.cell(30, 8, str(port), border=1, new_x=XPos.RIGHT, new_y=YPos.TOP, align='C')
                banner_text = banner if banner else 'No banner received'
                # Handle long banners by wrapping text
                if len(banner_text) > 60:
                    banner_text = banner_text[:60] + '...'
                pdf.cell(160, 8, banner_text, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
        else:
            pdf.set_font('Helvetica', '', 10)
            pdf.cell(0, 10, 'No open ports found.', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
        
        # Footer note
        pdf.ln(10)
        pdf.set_font('Helvetica', 'I', 8)
        pdf.cell(0, 10, 'Generated by NetGuard Network Scanner - For authorized use only', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        
        # Save PDF (always overwrite the same filename)
        pdf.output(filename)
        print(f"\n{Fore.GREEN}[+] PDF report generated: {filename}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[-] Error generating PDF report: {str(e)}{Style.RESET_ALL}")


def main():
    """Main function to orchestrate the network scan"""
    global target_ip, start_time, open_ports
    
    parser = argparse.ArgumentParser(
        description="NetGuard - multi-threaded TCP port scanner with banner grabbing and PDF reporting.")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="common",
                        help="Ports to scan: 'common' (default), 'all' (1-65535), "
                             "a range like 1-1024, or a CSV like 22,80,443")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="Number of concurrent worker threads (default: 100)")
    args = parser.parse_args()

    target_ip = resolve_target(args.target)
    ports_to_scan = parse_ports(args.ports)
    max_workers = args.workers
    start_time = datetime.now()
    
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}NetGuard Network Scanner{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Target IP: {target_ip}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Scanning {len(ports_to_scan)} ports...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Start Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    try:
        # Multi-threaded port scanning
        # ThreadPoolExecutor manages a pool of worker threads
        # max_workers controls the number of concurrent connections
        # Too many threads can overwhelm the network or target host
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all port scan tasks to the thread pool
            # Each task scans one port independently
            future_to_port = {
                executor.submit(scan_port, target_ip, port): port 
                for port in ports_to_scan
            }
            
            # Process completed tasks as they finish
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    port_num, status, banner = future.result()
                    
                    # Thread-safe result storage
                    if status == 'open':
                        with lock:
                            open_ports.append((port_num, banner))
                        print_result(port_num, status, banner)
                    elif status == 'error':
                        print_result(port_num, status)
                        
                except Exception as e:
                    print(f"{Fore.RED}[-] Port {port} - Exception: {str(e)}{Style.RESET_ALL}")
        
        # Scan complete
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Scan completed!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Duration: {duration:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Open ports found: {len(open_ports)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        # Generate PDF report
        if open_ports:
            # Sort open ports by port number
            open_ports.sort(key=lambda x: x[0])
            generate_pdf_report(target_ip, start_time, open_ports, total_scanned=len(ports_to_scan))
        else:
            print(f"{Fore.YELLOW}[!] No open ports found. PDF report not generated.{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user (Ctrl+C){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Partial results: {len(open_ports)} open ports found{Style.RESET_ALL}")
        
        # Generate partial report if any ports were found
        if open_ports:
            open_ports.sort(key=lambda x: x[0])
            # Always save the partial/interrupt report to the same filename so it overwrites
            generate_pdf_report(target_ip, start_time, open_ports, total_scanned=len(ports_to_scan))
        
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[-] Unexpected error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()