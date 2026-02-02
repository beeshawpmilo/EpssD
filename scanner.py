#!/usr/bin/env python3
"""
Enhanced Port Scanner with Service Detection
Author: Emmanuel Ohiren Akhibi
Description: Fast TCP port scanner with service identification and progress tracking
"""

import socket
import sys
from datetime import datetime
import threading
from queue import Queue
from colorama import Fore, Style, init
from tqdm import tqdm
import argparse
from export_handler import export_to_json, export_to_csv, export_to_text

# Initialize colorama
init(autoreset=True)

# Thread-safe data structures
open_ports = []
lock = threading.Lock()
progress_bar = None

# Common port-to-service mapping
PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

def get_service_name(port):
    """
    Get service name for a port
    
    Args:
        port (int): Port number
    
    Returns:
        str: Service name or 'Unknown'
    """
    return PORT_SERVICES.get(port, "Unknown")

def grab_banner(target_ip, port):
    """
    Attempt to grab service banner
    
    Args:
        target_ip (str): IP address
        port (int): Port number
    
    Returns:
        str: Banner text or empty string
    """
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((target_ip, port))
        
        # Try to receive banner
        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        return banner[:50] if banner else ""
    except:
        return ""

def scan_port(target_ip, port):
    """
    Scan a single port on target IP
    
    Args:
        target_ip (str): IP address to scan
        port (int): Port number to check
    
    Returns:
        dict: Port information if open, None otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        
        if result == 0:
            service = get_service_name(port)
            banner = grab_banner(target_ip, port)
            
            return {
                'port': port,
                'service': service,
                'banner': banner
            }
        return None
    except:
        return None

def worker(target_ip, queue):
    """
    Worker thread function
    
    Args:
        target_ip (str): IP address to scan
        queue (Queue): Queue containing ports to scan
    """
    global progress_bar
    
    while not queue.empty():
        port = queue.get()
        
        result = scan_port(target_ip, port)
        
        if result:
            with lock:
                open_ports.append(result)
                tqdm.write(f"{Fore.GREEN}[+] Port {result['port']}: OPEN - {result['service']}{Style.RESET_ALL}")
        
        # Update progress bar
        if progress_bar:
            progress_bar.update(1)
        
        queue.task_done()

def validate_ip(ip):
    """
    Validate IP address format
    
    Args:
        ip (str): IP address to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Enhanced Port Scanner v3.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python scanner.py -t 192.168.1.1 -p 1-100
  python scanner.py -t scanme.nmap.org -p common
  python scanner.py -t 10.0.0.1 -p 1-65535 -o json
  python scanner.py -t example.com --threads 200
        '''
    )
    
    parser.add_argument('-t', '--target', 
                        help='Target IP address or hostname')
    
    parser.add_argument('-p', '--ports',
                        default='common',
                        help='Port range: common, all, 1-1024, or custom range (e.g., 80-443)')
    
    parser.add_argument('-o', '--output',
                        choices=['json', 'csv', 'txt'],
                        help='Export results to file')
    
    parser.add_argument('--threads',
                        type=int,
                        default=100,
                        help='Number of threads (default: 100)')
    
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='Verbose output (show closed ports)')
    
    return parser.parse_args()

def get_port_list(port_arg):
    """
    Convert port argument to list of ports
    
    Args:
        port_arg (str): Port argument (common, all, or range)
    
    Returns:
        list: List of ports to scan
    """
    if port_arg == 'common':
        return list(PORT_SERVICES.keys())
    elif port_arg == 'all':
        return range(1, 65536)
    elif '-' in port_arg:
        start, end = map(int, port_arg.split('-'))
        return range(start, end + 1)
    else:
        return [int(port_arg)]

def interactive_mode():
    """Run scanner in interactive mode"""
    global progress_bar
    
    # Banner
    print(f"{Fore.CYAN}" + "=" * 50)
    print("Enhanced Port Scanner v3.0")
    print("By: Olaoluwa Aminu Taiwo")
    print("=" * 50 + f"{Style.RESET_ALL}\n")
    
    # Get target from user
    target = input("Enter target IP address or hostname: ")
    
    # Resolve hostname if needed
    try:
        target_ip = socket.gethostbyname(target)
        if target != target_ip:
            print(f"Resolved {target} to {target_ip}\n")
    except socket.gaierror:
        print(f"{Fore.RED}Error: Could not resolve hostname{Style.RESET_ALL}")
        sys.exit()
    
    # Validate IP
    if not validate_ip(target_ip):
        print(f"{Fore.RED}Error: Invalid IP address{Style.RESET_ALL}")
        sys.exit()
    
    # Get port range
    print("\nPort range options:")
    print("1. Common ports (15 ports)")
    print("2. Well-known ports (1-1024)")
    print("3. All ports (1-65535)")
    print("4. Custom range")
    
    choice = input("\nSelect option (1-4): ")
    
    if choice == "1":
        ports = list(PORT_SERVICES.keys())
    elif choice == "2":
        ports = range(1, 1025)
    elif choice == "3":
        ports = range(1, 65536)
    elif choice == "4":
        start = int(input("Enter start port: "))
        end = int(input("Enter end port: "))
        ports = range(start, end + 1)
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
        sys.exit()
    
    ports_list = list(ports)
    num_threads = 100
    
    return target_ip, ports_list, num_threads, None

def main():
    """Main function to run the port scanner"""
    global progress_bar, open_ports
    
    # Reset open_ports for fresh scan
    open_ports = []
    
    # Parse arguments
    args = parse_arguments()
    
    # Check if interactive mode
    if not args.target:
        target_ip, ports_list, num_threads, output_format = interactive_mode()
    else:
        # CLI mode
        print(f"{Fore.CYAN}" + "=" * 50)
        print("Enhanced Port Scanner v3.0")
        print("By: Olaoluwa Aminu Taiwo")
        print("=" * 50 + f"{Style.RESET_ALL}\n")
        
        # Resolve target
        try:
            target_ip = socket.gethostbyname(args.target)
            if args.target != target_ip:
                print(f"Resolved {args.target} to {target_ip}\n")
        except socket.gaierror:
            print(f"{Fore.RED}Error: Could not resolve hostname{Style.RESET_ALL}")
            sys.exit()
        
        # Get port list
        ports_list = list(get_port_list(args.ports))
        num_threads = args.threads
        output_format = args.output
    
    # Display scan information
    print(f"\n{Fore.YELLOW}Scan Information:{Style.RESET_ALL}")
    print(f"Target IP: {target_ip}")
    print(f"Ports to scan: {len(ports_list)}")
    print(f"Threads: {num_threads}")
    print(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50 + "\n")
    
    # Create queue and add all ports
    port_queue = Queue()
    for port in ports_list:
        port_queue.put(port)
    
    # Adjust thread count
    num_threads = min(num_threads, len(ports_list))
    
    # Start time
    start_time = datetime.now()
    
    # Create progress bar
    progress_bar = tqdm(total=len(ports_list), desc="Scanning", unit="port")
    
    # Create and start threads
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(target_ip, port_queue))
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    # Wait for all threads to complete
    port_queue.join()
    progress_bar.close()
    
    # End time
    end_time = datetime.now()
    
    # Summary
    print("\n" + "=" * 50)
    print(f"{Fore.CYAN}Scan Summary{Style.RESET_ALL}")
    print("=" * 50)
    print(f"Completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Time elapsed: {end_time - start_time}")
    print(f"Total ports scanned: {len(ports_list)}")
    print(f"Open ports found: {Fore.GREEN}{len(open_ports)}{Style.RESET_ALL}")
    
    if open_ports:
        print(f"\n{Fore.YELLOW}Open Ports:{Style.RESET_ALL}")
        open_ports.sort(key=lambda x: x['port'])
        
        for port_info in open_ports:
            banner_text = f" | {port_info['banner'][:30]}..." if port_info['banner'] else ""
            print(f"  {port_info['port']}/tcp - {port_info['service']}{banner_text}")
    
    # Ask if user wants to export (if not already specified in CLI)
    if output_format is None and open_ports:
        export_choice = input(f"\n{Fore.YELLOW}Export results? (json/csv/txt/no): {Style.RESET_ALL}").lower()
        output_format = export_choice if export_choice in ['json', 'csv', 'txt'] else None
    
    # Handle export
    if output_format and open_ports:
        scan_data = {
            'target': target_ip,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'duration': str(end_time - start_time),
            'total_ports': len(ports_list),
            'open_count': len(open_ports),
            'open_ports': open_ports
        }
        
        if output_format == 'json':
            filepath = export_to_json(scan_data)
        elif output_format == 'csv':
            filepath = export_to_csv(scan_data)
        else:
            filepath = export_to_text(scan_data)
        
        print(f"{Fore.GREEN}Results exported to: {filepath}{Style.RESET_ALL}")
    
    print("\n" + "=" * 50)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit()
    return filename
```
