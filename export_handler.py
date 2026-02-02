"""
Export functionality for port scanner
Author: Olaoluwa Aminu Taiwo
"""

import json
import csv
from datetime import datetime
import os

def ensure_results_dir():
    """Create results directory if it doesn't exist"""
    if not os.path.exists('results'):
        os.makedirs('results')

def export_to_json(scan_data, filename=None):
    """
    Export scan results to JSON
    
    Args:
        scan_data (dict): Scan results dictionary
        filename (str): Custom filename (optional)
    
    Returns:
        str: Path to saved file
    """
    ensure_results_dir()
    
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"results/scan_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(scan_data, f, indent=4)
    
    return filename

def export_to_csv(scan_data, filename=None):
    """
    Export scan results to CSV
    
    Args:
        scan_data (dict): Scan results dictionary
        filename (str): Custom filename (optional)
    
    Returns:
        str: Path to saved file
    """
    ensure_results_dir()
    
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"results/scan_{timestamp}.csv"
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write header
        writer.writerow(['Port', 'Service', 'State', 'Banner'])
        
        # Write open ports
        for port_info in scan_data['open_ports']:
            writer.writerow([
                port_info['port'],
                port_info['service'],
                'OPEN',
                port_info.get('banner', '')
            ])
    
    return filename

def export_to_text(scan_data, filename=None):
    """
    Export scan results to text file
    
    Args:
        scan_data (dict): Scan results dictionary
        filename (str): Custom filename (optional)
    
    Returns:
        str: Path to saved file
    """
    ensure_results_dir()
    
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"results/scan_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write("=" * 50 + "\n")
        f.write("PORT SCAN REPORT\n")
        f.write("=" * 50 + "\n\n")
        
        f.write(f"Target: {scan_data['target']}\n")
        f.write(f"Scan Date: {scan_data['scan_date']}\n")
        f.write(f"Scan Duration: {scan_data['duration']}\n")
        f.write(f"Total Ports Scanned: {scan_data['total_ports']}\n")
        f.write(f"Open Ports Found: {scan_data['open_count']}\n\n")
        
        f.write("=" * 50 + "\n")
        f.write("OPEN PORTS\n")
        f.write("=" * 50 + "\n\n")
        
        for port_info in scan_data['open_ports']:
            f.write(f"Port: {port_info['port']}/tcp\n")
            f.write(f"Service: {port_info['service']}\n")
            if port_info.get('banner'):
                f.write(f"Banner: {port_info['banner']}\n")
            f.write("-" * 30 + "\n\n")
    
    return filename
```
