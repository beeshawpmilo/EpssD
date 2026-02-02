#!/usr/bin/env python3
"""
Enhanced Port Scanner with Service Detection
Author: Emmanuel Ohiren Akhibi
Description: Fast TCP port scanner with service identification and progress tracking
"""

import socket
import sys
import json
import csv
from datetime import datetime
import threading
from queue import Queue, Empty
from colorama import Fore, Style, init
from tqdm import tqdm
import argparse

# Initialize colorama
init(autoreset=True)

# Thread-safe data structures
open_ports = []
lock = threading.Lock()
progress_bar = None

# Common port-to-service mapping
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
}

# --- Export Handlers (Replaces missing export_handler module) ---
def export_to_json(data):
    filename = f"scan_{data['target']}_{datetime.now().strftime('%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
    return filename

def export_to_csv(data):
    filename = f"scan_{data['target']}_{datetime.now().strftime('%H%M%S')}.csv"
    keys = data['open_ports'][0].keys() if data['open_ports'] else []
    with open(filename, 'w', newline='') as f:
        dict_writer = csv.DictWriter(f, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(data['open_ports'])
    return filename

def export_to_text(data):
    filename = f"scan_{data['target']}_{datetime.now().strftime('%H%M%S')}.txt"
    with open(filename, 'w') as f:
        f.write(f"Scan Report for {data['target']}\n" + "="*30 + "\n")
        for p in data['open_ports']:
            f.write(f"Port: {p['port']} | Service: {p['service']} | Banner: {p['banner']}\n")
    return filename

# --- Scanning Logic ---

def get_service_name(port):
    return PORT_SERVICES.get(port, "Unknown")

def grab_banner(target_ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(1.5)
        sock.connect((target_ip, port))
        # Simple probe for HTTP; many services respond to this or just send a banner on connect
        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner.replace('\n', ' ').replace('\r', '')[:50]
    except:
        return ""

def scan_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        
        if result == 0:
            service = get_service_name(port)
            banner = grab_banner(target_ip, port)
            return {'port': port, 'service': service, 'banner': banner}
        return None
    except:
        return None

def worker(target_ip, queue):
    global progress_bar
    while True:
        try:
            port = queue.get_nowait()
        except Empty:
            break
            
        result = scan_port(target_ip, port)
        if result:
            with lock:
                open_ports.append(result)
                tqdm.write(f"{Fore.GREEN}[+] Port {result['port']}: OPEN - {result['service']}{Style.RESET_ALL}")
        
        if progress_bar:
            with lock:
                progress_bar.update(1)
        queue.task_done()

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Enhanced Port Scanner v3.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:\n  python scanner.py -t 192.168.1.1 -p 1-100\n  python scanner.py -t google.com --threads 200'''
    )
    parser.add_argument('-t', '--target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='common', help='Port range: common, all, 1-1024, or 80-443')
    parser.add_argument('-o', '--output', choices=['json', 'csv', 'txt'], help='Export results to file')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads (default: 100)')
    return parser.parse_args()

def get_port_list(port_arg):
    if port_arg == 'common':
        return list(PORT_SERVICES.keys())
    elif port_arg == 'all':
        return range(1, 65536)
    elif '-' in port_arg:
        try:
            start, end = map(int, port_arg.split('-'))
            return range(start, end + 1)
        except ValueError:
            print(f"{Fore.RED}Invalid range format. Use Start-End (e.g. 1-1000){Style.RESET_ALL}")
            sys.exit(1)
    else:
        return [int(port_arg)]

def main():
    global progress_bar, open_ports
    open_ports = []
    args = parse_arguments()
    
    # Header
    print(f"{Fore.CYAN}" + "=" * 50)
    print("Enhanced Port Scanner v3.0")
    print("By: Emmanuel Ohiren Akhibi")
    print("=" * 50 + f"{Style.RESET_ALL}\n")

    target = args.target
    if not target:
        target = input("Enter target IP address or hostname: ")
    
    if not target:
        print(f"{Fore.RED}Error: No target specified.{Style.RESET_ALL}")
        return

    try:
        target_ip = socket.gethostbyname(target)
        if target != target_ip:
            print(f"Resolved {target} to {target_ip}")
    except socket.gaierror:
        print(f"{Fore.RED}Error: Could not resolve hostname{Style.RESET_ALL}")
        sys.exit()

    ports_list = list(get_port_list(args.ports))
    num_threads = min(args.threads, len(ports_list))
    
    # Queue setup
    port_queue = Queue()
    for port in ports_list:
        port_queue.put(port)
    
    print(f"Scanning {len(ports_list)} ports on {target_ip} using {num_threads} threads...\n")
    start_time = datetime.now()
    
    progress_bar = tqdm(total=len(ports_list), desc="Scanning", unit="port", leave=False)
    
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(target_ip, port_queue))
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    port_queue.join()
    progress_bar.close()
    
    end_time = datetime.now()
    duration = end_time - start_time

    # Summary Display
    print("\n" + "=" * 50)
    print(f"{Fore.CYAN}Scan Summary{Style.RESET_ALL}")
    print(f"Time elapsed: {duration}")
    print(f"Open ports found: {Fore.GREEN}{len(open_ports)}{Style.RESET_ALL}")
    
    if open_ports:
        open_ports.sort(key=lambda x: x['port'])
        for p in open_ports:
            banner = f" | {p['banner']}" if p['banner'] else ""
            print(f"  {p['port']}/tcp - {p['service']}{banner}")

        output_format = args.output
        if not output_format:
            choice = input(f"\nExport results? (json/csv/txt/no): ").lower()
            output_format = choice if choice in ['json', 'csv', 'txt'] else None

        if output_format:
            scan_data = {
                'target': target_ip,
                'duration': str(duration),
                'open_ports': open_ports
            }
            if output_format == 'json': filepath = export_to_json(scan_data)
            elif output_format == 'csv': filepath = export_to_csv(scan_data)
            else: filepath = export_to_text(scan_data)
            print(f"{Fore.GREEN}Results exported to: {filepath}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Scan interrupted.{Style.RESET_ALL}")
        sys.exit()
