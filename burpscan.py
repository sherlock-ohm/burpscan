import argparse
import xml.etree.ElementTree as ET
from lxml import etree
import subprocess
import requests
import sys
import io
import re
import ipaddress
import os
import json
from urllib.parse import urlparse, quote
from datetime import datetime
import random

# ----------------------------
# ASCII Banner
# ----------------------------

def display_banner():
    """Display a fancy ASCII art banner for BurpScan"""
    banner = """
 ▄▄▄▄    █    ██  ██▀███   ██▓███    ██████  ▄████▄   ▄▄▄       ███▄    █
▓█████▄  ██  ▓██▒▓██ ▒ ██▒▓██░  ██▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █
▒██▒ ▄██▓██  ▒██░▓██ ░▄█ ▒▓██░ ██▓▒░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
▒██░█▀  ▓▓█  ░██░▒██▀▀█▄  ▒██▄█▓▒ ▒  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
░▓█  ▀█▓▒▒█████▓ ░██▓ ▒██▒▒██▒ ░  ░▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░
░▒▓███▀▒░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒
▒░▒   ░ ░░▒░ ░ ░   ░▒ ░ ▒░░▒ ░     ░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░
 ░    ░  ░░░ ░ ░   ░░   ░ ░░       ░  ░  ░  ░          ░   ▒      ░   ░ ░
 ░         ░        ░                    ░  ░ ░            ░  ░         ░
      ░                                     ░
"""
    
    # ANSI color codes for a cool effect
    colors = [
        "\033[1;31m",  # Red
        "\033[1;32m",  # Green
        "\033[1;34m",  # Blue
        "\033[1;35m",  # Purple
        "\033[1;36m"   # Cyan
    ]
    
    # Choose a random color
    color = random.choice(colors)
    reset = "\033[0m"
    
    print(f"{color}{banner}{reset}")
    print(f"{color}Automated Web Application Security Testing with Burp Suite{reset}")
    print(f"{color}v1.0 - https://github.com/sherlock-ohm/burpscan{reset}")
    print("\n")

# ----------------------------
# Argument Parsing
# ----------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "       python3 burpscan.py <file.nessus>\n"
            "       python3 burpscan.py <file.xml>\n"
            "       python3 burpscan.py <file.txt>\n"
            "       python3 burpscan.py '<IP>'\n"
            "       python3 burpscan.py '<CIDR>'\n"
            "       python3 burpscan.py '<URL>'\n"
            "       OR\n"
            "       cat <whatever> | python3 burpscan.py\n"
            "       echo '<whatever>' | python3 burpscan.py\n\n"
            "This script will selectively run an unauthenticated active scan in Burp Suite.\n"
            "Ensure you visually inspect each input to confirm it can handle a scan without causing issues!\n\n"
            "- Go to Settings -> Suite -> REST API\n"
            "- Select 'Service running'\n"
            "- Purge httpx from Kali and install ProjectDiscovery's version\n"
            "- Install and set up bchecks and any other extensions you prefer."
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "input", 
        nargs="?", 
        help="Path to .nessus/.xml/.txt file OR IP/domain/CIDR/URL OR use stdin"
    )
    parser.add_argument(
        "--debug", 
        action="store_true", 
        help="Enable verbose debug output"
    )
    parser.add_argument(
        "--api-key", 
        help="API key (You can add one in Burp Suite settings)"
    )
    parser.add_argument(
        "--hailmary", 
        action="store_true", 
        help="Automatically answer 'yes' to all prompts (Use with caution!)"
    )
    parser.add_argument(
        "--katana", 
        action="store_true", 
        help="Run katana crawler against simple endpoints before sending to Burp Suite"
    )
    
    return parser.parse_args()

# ----------------------------
# Parsers for Nessus and Nmap
# ----------------------------

def parse_nessus(xml_bytes_io, debug=False):
    root = ET.parse(xml_bytes_io).getroot()
    targets = set()
    
    # Track how many targets we found with hostnames vs IPs
    hostname_count = 0
    ip_only_count = 0
    
    for report_host in root.findall(".//ReportHost"):
        host_ip = None
        hostname = None
        
        # The 'name' attribute in ReportHost can be either an IP or hostname
        name = report_host.get('name')
        
        # Try to determine if this is an IP or hostname
        try:
            ipaddress.ip_address(name)
            host_ip = name
        except ValueError:
            # Not a valid IP, treat as hostname
            hostname = name
        
        # Look for host properties to get both IP and hostname if possible
        for tag in report_host.findall(".//tag"):
            tag_name = tag.get('name')
            if tag_name == 'host-ip' and not host_ip:
                host_ip = tag.text
            elif tag_name == 'hostname' and not hostname:
                hostname = tag.text
        
        # Prefer hostname over IP if available, otherwise use IP
        target_host = hostname if hostname else host_ip
        if not target_host:
            if debug:
                print(f"[DEBUG] Could not determine host IP or name for a ReportHost, skipping")
            continue
            
        if hostname:
            hostname_count += 1
        else:
            ip_only_count += 1
            
        # Process port information from report items
        http_ports = set()  # Track HTTP/HTTPS ports specifically
        
        for report_item in report_host.findall(".//ReportItem"):
            port = report_item.get('port')
            protocol = report_item.get('protocol', 'tcp').lower()
            service_name = report_item.get('svc_name', '').lower()
            plugin_name = report_item.get('pluginName', '').lower()
            
            # Skip if not TCP protocol
            if protocol != "tcp":
                continue
                
            # Skip ports that are likely not HTTP/HTTPS
            # Commonly filtered: low ports, SSH, FTP, SMTP, etc.
            if service_name in ['ssh', 'ftp', 'smtp', 'pop3', 'imap', 'telnet', 'rpc']:
                continue
                
            # Explicitly add known web ports
            if (service_name in ['www', 'http', 'https'] or 
                'http' in service_name or
                'web' in plugin_name or
                'http' in plugin_name):
                http_ports.add(port)
                
            # Always add port 80 and 443
            if port in ['80', '443']:
                http_ports.add(port)
            
            # General case - add all TCP ports as targets
            targets.add(f"{target_host}:{port}")
        
        # If we found specific HTTP ports, we could note that
        if debug and http_ports:
            ports_str = ', '.join(sorted(http_ports))
            print(f"[DEBUG] Found HTTP-related ports for {target_host}: {ports_str}")
    
    if debug:
        print(f"[DEBUG] Parsed {len(targets)} TCP targets from Nessus")
        print(f"[DEBUG] Found {hostname_count} hosts with hostnames, {ip_only_count} with IPs only")
    
    return sorted(targets)

def parse_nmap(xml_bytes_io, debug=False):
    root = etree.parse(xml_bytes_io).getroot()
    targets = set()
    for host in root.xpath('//host'):
        # Get IP address
        addr_elem = host.find('address')
        if addr_elem is None or addr_elem.get('addrtype') != 'ipv4':
            continue
        ip = addr_elem.get('addr')
        
        # Try to get hostname (prioritize user-provided hostnames)
        hostname = ip  # Default to IP if no hostname
        hostnames = host.findall('.//hostname')
        for hn in hostnames:
            if hn.get('type') == 'user':
                hostname = hn.get('name')
                break  # Prioritize user-provided hostname
        
        # Get open ports
        ports = host.findall('.//port')
        for port in ports:
            portid = int(port.get('portid'))
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            targets.add(f"{hostname}:{portid}")
    
    if debug:
        print(f"[DEBUG] Parsed {len(targets)} open TCP ports from Nmap")
    return sorted(targets)

# ----------------------------
# XML Cleaner and Format Detection
# ----------------------------

def detect_and_parse_xml(source_stream, debug=False):
    raw_bytes = source_stream.read().lstrip()
    raw_text = raw_bytes.decode('utf-8', errors='ignore')
    cleaned_text = re.sub(r'<\?xml.*?\?>', '', raw_text)
    cleaned_text = re.sub(r'<!DOCTYPE[^>]*>', '', cleaned_text)
    cleaned_text = re.sub(r'<\?xml-stylesheet[^>]*\?>', '', cleaned_text)

    if "<NessusClientData_v2" in cleaned_text:
        match = re.search(r"(<NessusClientData_v2.*?</NessusClientData_v2>)", cleaned_text, re.DOTALL)
        if not match:
            print("❌ Couldn't extract valid .nessus content.")
            sys.exit(1)
        final_text = match.group(1)
        if debug: print("[DEBUG] Detected .nessus format")
    elif "<nmaprun" in cleaned_text:
        match = re.search(r"(<nmaprun.*?</nmaprun>)", cleaned_text, re.DOTALL)
        if not match:
            print("❌ Couldn't extract valid Nmap XML content.")
            sys.exit(1)
        final_text = match.group(1)
        if debug: print("[DEBUG] Detected Nmap .xml format")
    else:
        print("❌ Unknown XML format. Expected .nessus or Nmap .xml")
        sys.exit(1)

    if debug:
        print("[DEBUG] Cleaned XML preview:")
        print(final_text[:300])

    try:
        return parse_nessus(io.BytesIO(final_text.encode('utf-8')), debug) if 'NessusClientData_v2' in final_text \
            else parse_nmap(io.BytesIO(final_text.encode('utf-8')), debug)
    except Exception as e:
        print(f"❌ Failed to parse XML: {e}")
        sys.exit(1)

# ----------------------------
# URL Cleaning and Sanitization
# ----------------------------

def sanitize_url(url, debug=False):
    """Clean a URL to make it suitable for the Burp API"""
    # Remove any whitespace characters at the start and end
    cleaned_url = url.strip()
    
    # Replace spaces with %20
    if ' ' in cleaned_url:
        if debug:
            print(f"[DEBUG] Found and replacing spaces in URL: {cleaned_url}")
        cleaned_url = cleaned_url.replace(' ', '%20')
    
    # Additional sanitization if needed
    # Make sure the URL is properly formatted
    if not cleaned_url.startswith(('http://', 'https://')):
        if debug:
            print(f"[DEBUG] URL missing protocol: {cleaned_url}")
        # If it's just a domain or IP, assume http://
        if re.match(r'^[a-zA-Z0-9\.\-]+(\:[0-9]+)?(/.*)?$', cleaned_url):
            cleaned_url = 'http://' + cleaned_url
    
    return cleaned_url

def sanitize_urls(urls, debug=False):
    """Clean a list of URLs to make them suitable for the Burp API"""
    sanitized = []
    invalid = []
    
    for url in urls:
        try:
            clean_url = sanitize_url(url, debug)
            # Basic validation check
            parsed = urlparse(clean_url)
            if parsed.netloc:
                sanitized.append(clean_url)
            else:
                if debug:
                    print(f"[DEBUG] Invalid URL detected and skipped: {url}")
                invalid.append(url)
        except Exception as e:
            if debug:
                print(f"[DEBUG] Error sanitizing URL {url}: {e}")
            invalid.append(url)
    
    if invalid and debug:
        print(f"[DEBUG] Skipped {len(invalid)} invalid URLs")
    
    return sanitized

def is_complex_url(url, debug=False):
    """Check if a URL has paths or parameters beyond the hostname"""
    try:
        # First sanitize to ensure proper URL format
        clean_url = sanitize_url(url, debug)
        parsed = urlparse(clean_url)
        
        # URL has path beyond '/' or has query parameters
        if (parsed.path and parsed.path != '/' and parsed.path != '') or parsed.query:
            if debug:
                print(f"[DEBUG] Complex URL detected: {clean_url}")
            return True
        
        return False
    except Exception:
        # If we can't parse it, assume it's not complex
        return False

def contains_complex_urls(urls, debug=False):
    """Check if any URL in the list is complex (has paths or parameters)"""
    complex_urls = []
    
    for url in urls:
        if is_complex_url(url, debug):
            complex_urls.append(url)
            
            # Only collect a few examples if there are many
            if len(complex_urls) >= 5:
                break
    
    return complex_urls

# ----------------------------
# Scan Pipeline
# ----------------------------

def run_httpx_filter(targets, debug=False):
    if debug:
        print(f"[DEBUG] Running httpx on {len(targets)} targets")
        for t in targets:
            print(f"[httpx input] {t}")
    try:
        process = subprocess.run(
            ["httpx", "-silent"],
            input="\n".join(targets),
            text=True,
            capture_output=True,
            check=True
        )
        output = process.stdout.strip().splitlines()
        if debug:
            print(f"[DEBUG] httpx returned {len(output)} targets:")
            for line in output:
                print(f"[httpx output] {line}")
        return list(dict.fromkeys(output))
    except subprocess.CalledProcessError as e:
        print(f"❌ Error running httpx: {e.stderr}")
        sys.exit(1)

def group_urls_by_domain(urls, debug=False):
    """Group URLs by domain, separating simple endpoints from those with paths/parameters"""
    simple_endpoints = []
    complex_urls_by_domain = {}
    
    for url in urls:
        parsed = urlparse(url)
        
        # Check if URL has path beyond '/' or has query parameters
        if (parsed.path and parsed.path != '/' and parsed.path != '') or parsed.query:
            domain = parsed.netloc
            if domain not in complex_urls_by_domain:
                complex_urls_by_domain[domain] = []
            complex_urls_by_domain[domain].append(url)
            if debug:
                print(f"[DEBUG] Grouped complex URL {url} under domain {domain}")
        else:
            simple_endpoints.append(url)
            if debug:
                print(f"[DEBUG] Identified simple endpoint: {url}")
    
    return simple_endpoints, complex_urls_by_domain

def run_katana(url, debug=False):
    if debug:
        print(f"[DEBUG] Running katana on {url}")
    
    # Escape the URL to handle special characters safely
    escaped_url = url.replace('"', '\\"')
    
    cmd = f'katana -jc -kf all -rl 30 -iqp -f qurl,udir -u "{escaped_url}"'
    
    if debug:
        print(f"[DEBUG] Running command: {cmd}")
    
    try:
        process = subprocess.run(
            cmd,
            shell=True,
            text=True,
            capture_output=True
        )
        
        if process.returncode != 0:
            if debug:
                print(f"[DEBUG] katana failed with return code {process.returncode}")
                print(f"[DEBUG] stderr: {process.stderr}")
            print(f"❌ Error running katana: {process.stderr}")
            return []
        
        output = process.stdout.strip().splitlines()
        
        if debug:
            print(f"[DEBUG] katana returned {len(output)} URLs:")
            for line in output[:10]:  # Show first 10 results
                print(f"[katana output] {line}")
        
        # Remove exact duplicates
        unique_urls = list(dict.fromkeys(output))
        
        # Sanitize URLs before returning
        return sanitize_urls(unique_urls, debug)
    
    except Exception as e:
        print(f"❌ Error executing katana: {str(e)}")
        if debug:
            import traceback
            print(traceback.format_exc())
        return []

def save_urls_to_file(urls, target_url):
    """Save URLs to a file in the current working directory"""
    # Create a clean filename based on the target and timestamp
    parsed = urlparse(target_url)
    domain = parsed.netloc.replace(':', '_')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"katana_{domain}_{timestamp}.txt"
    
    try:
        with open(filename, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")
        print(f"✅ Saved {len(urls)} URLs to {filename}")
        return filename
    except Exception as e:
        print(f"❌ Failed to save URLs to file: {e}")
        return None

def group_urls_by_subdomain(urls, debug=False):
    """Group URLs by their specific subdomain for separate scans"""
    url_groups = {}
    
    for url in urls:
        parsed = urlparse(url)
        hostname = parsed.netloc
        
        if hostname not in url_groups:
            url_groups[hostname] = []
        
        url_groups[hostname].append(url)
        
        if debug:
            print(f"[DEBUG] Grouped URL {url} under hostname {hostname}")
    
    return url_groups

def send_burp_scan_for_subdomain(subdomain, urls, api_url, debug=False, hailmary=False):
    """Send URLs to Burp API with scope limited to a single specific subdomain"""
    # First, sanitize all URLs to ensure they're API-friendly
    clean_urls = sanitize_urls(urls, debug)
    
    if len(clean_urls) < len(urls):
        print(f"⚠️ Filtered out {len(urls) - len(clean_urls)} invalid URLs for {subdomain}")
    
    if not clean_urls:
        print(f"❌ No valid URLs to scan for {subdomain} after sanitization")
        return False
    
    # Format the payload with scope for this specific subdomain only
    payload = {
        "urls": clean_urls,
        "protocol_option": "specified",
        "scope": {
            "include": [{"rule": subdomain}],
            "type": "SimpleScope"
        }
    }
    
    try:
        if debug:
            print(f"[DEBUG] Sending to Burp API: {len(clean_urls)} URLs for {subdomain}")
            print(f"[DEBUG] Scope includes only: {subdomain}")
            if len(clean_urls) <= 5:  # Only show full payload for small URL lists
                print(f"[DEBUG] Payload: {json.dumps(payload)}")
        
        response = requests.post(api_url, json=payload)
        
        if debug:
            print(f"[DEBUG] Response status: {response.status_code}")
            print(f"[DEBUG] Response body: {response.text}")
        
        if response.status_code == 201:
            print(f"✅ Scan started for {subdomain} with {len(clean_urls)} URLs")
            return True
        else:
            print(f"❌ Failed to scan {subdomain}: {response.status_code} {response.text}")
            
            # Always ask user when there are API errors, even in hailmary mode
            retry = prompt_user(f"Do you want to try scanning {subdomain} again? [y/N]: ", False)  # Force manual prompt
            if retry == 'y':
                return send_burp_scan_for_subdomain(subdomain, clean_urls, api_url, debug, hailmary)
            else:
                # Save URLs to file before giving up
                print(f"Saving URLs for {subdomain} to a file for later use...")
                save_urls_to_file(clean_urls, f"http://{subdomain}")
                return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Error contacting Burp API for {subdomain}: {e}")
        
        # Always ask user when there are API errors, even in hailmary mode
        retry = prompt_user(f"Do you want to try scanning {subdomain} again? [y/N]: ", False)  # Force manual prompt
        if retry == 'y':
            return send_burp_scan_for_subdomain(subdomain, clean_urls, api_url, debug, hailmary)
        else:
            # Save URLs to file before giving up
            print(f"Saving URLs for {subdomain} to a file for later use...")
            save_urls_to_file(clean_urls, f"http://{subdomain}")
            return False

def process_single_subdomain(subdomain, urls, api_url, debug=False, hailmary=False):
    """Process a single subdomain immediately after confirmation"""
    print(f"\n Subdomain '{subdomain}' has {len(urls)} URLs")
    
    # Ask for confirmation (auto-yes in hailmary mode)
    choice = prompt_user(f"Scan {len(urls)} URLs for '{subdomain}'? [y/N]: ", hailmary)
    
    if choice == 'y':
        print(f" Sending {len(urls)} URLs for subdomain '{subdomain}' to Burp Suite...")
        if send_burp_scan_for_subdomain(subdomain, urls, api_url, debug, hailmary):
            return True
    return False

def process_subdomain_groups(url_groups, api_url, debug=False, hailmary=False):
    """Process each subdomain group with a separate scan"""
    total_groups = len(url_groups)
    successful_groups = 0
    
    print(f"\n Processing {total_groups} different subdomains/hosts for individual scans")
    
    for subdomain, urls in url_groups.items():
        if process_single_subdomain(subdomain, urls, api_url, debug, hailmary):
            successful_groups += 1
    
    print(f"\n✅ Completed processing {successful_groups}/{total_groups} subdomain scans")
    return successful_groups > 0

def prompt_user(prompt, hailmary=False):
    """
    Prompt the user for input. If hailmary mode is active, always return 'y'.
    """
    if hailmary:
        print(f"{prompt} [Automatically selected 'y' due to --hailmary]")
        return 'y'
    try:
        with open('/dev/tty', 'r') as tty:
            print(prompt, end='', flush=True)
            return tty.readline().strip().lower()
    except Exception:
        return 'n'

# ----------------------------
# Helper for direct input
# ----------------------------

def is_ip_or_cidr(value):
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False

def is_domain(value):
    return re.match(r"^(?!\-)([a-zA-Z0-9\-]{1,63}(?<!\-)\.)+[a-zA-Z]{2,}$", value) is not None

def parse_plain_text_lines(lines, debug=False):
    targets = []
    for target in lines:
        target = target.strip()
        if not target:
            continue
            
        # Handle URLs with spaces by replacing them with %20
        if ' ' in target and (target.startswith('http://') or target.startswith('https://') or '://' in target):
            if debug:
                print(f"[DEBUG] Converting spaces in URL: {target}")
            target = target.replace(' ', '%20')
            
        # Now process the cleaned target
        if re.match(r"^https?://[^\s]+$", target):
            targets.append(target)
        elif re.match(r"^[a-zA-Z0-9\-\.]+:\d+$", target):
            targets.append(target)
        elif is_ip_or_cidr(target):
            net = ipaddress.ip_network(target, strict=False)
            targets.extend([f"{ip}:80" for ip in net.hosts()])
        elif is_domain(target) or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            targets.extend([f"{target}:80", f"{target}:443"])
        else:
            # Try to handle it as potentially a URL without protocol
            if debug:
                print(f"[DEBUG] Attempting to process as URL without protocol: {target}")
            if '/' in target or '.' in target:  # Simple heuristic that it might be a URL
                url_candidate = 'http://' + target
                targets.append(url_candidate)
                if debug:
                    print(f"[DEBUG] Added with protocol: {url_candidate}")
            else:
                print(f"⚠ Skipping unrecognised input: {target}")
                
    return targets

# ----------------------------
# Main
# ----------------------------
def main():
    # Display the fancy banner
    display_banner()
    
    args = parse_arguments()
    api_key = args.api_key or ""
    api_url = f"http://localhost:1337/{api_key}/v0.1/scan" if api_key else "http://localhost:1337/v0.1/scan"
    hailmary = args.hailmary
    use_katana = args.katana


    if hailmary:
        print("⚠️ HailMary mode activated - automatically answering 'yes' to all prompts")
    
    if use_katana:
        print("️ Katana mode activated - will run katana crawler against simple endpoints")
    else:
        print(" Direct mode - sending httpx output directly to Burp Suite (no katana crawling)")

    raw_targets = []

    if args.input:
        if os.path.isfile(args.input):
            try:
                with open(args.input, 'rb') as f:
                    header = f.read(2048)
                    f.seek(0)

                    if header.strip().startswith(b"<"):
                        if args.debug:
                            print("[DEBUG] File appears to be XML, attempting to parse")
                        raw_targets = detect_and_parse_xml(f, args.debug)
                    else:
                        if args.debug:
                            print("[DEBUG] File appears to be plain text, parsing line by line")
                        lines = f.read().decode().splitlines()
                        raw_targets = parse_plain_text_lines(lines, args.debug)
            except Exception as e:
                print(f"❌ Failed to open file: {e}")
                sys.exit(1)
        elif is_ip_or_cidr(args.input) or is_domain(args.input):
            if args.debug:
                print(f"[DEBUG] Treating input as direct target: {args.input}")
            if is_ip_or_cidr(args.input):
                net = ipaddress.ip_network(args.input, strict=False)
                raw_targets = [f"{ip}:80" for ip in net.hosts()]
            else:
                raw_targets = [f"{args.input}:80", f"{args.input}:443"]
        elif re.match(r"^https?://[^\s]+$", args.input):
            # Handle space in URL input
            if ' ' in args.input:
                if args.debug:
                    print(f"[DEBUG] Converting spaces in input URL: {args.input}")
                args.input = args.input.replace(' ', '%20')
            raw_targets = [args.input]
            
            # Check for complex URL in direct input
            if use_katana and is_complex_url(args.input, args.debug):
                print("\n❌ ERROR: You specified --katana, but a complex URL was provided as input")
                print("❌ --katana mode only works with simple endpoints (URLs without paths or parameters)")
                print(f"❌ Complex URL detected: {args.input}")
                
                print("\nYou have two options:")
                print("1. Re-run without the --katana flag to send the URL directly to Burp Suite")
                print("2. Modify your input to only include the hostname (without path or parameters)")
                
                choice = prompt_user("\nDo you want to continue without using katana and send the URL directly to Burp Suite? [y/N]: ", False)
                
                if choice.lower() != 'y':
                    print("Exiting as requested.")
                    sys.exit(1)
                
                # Continue with direct mode (disable katana)
                print("\n Continuing in direct mode (--katana disabled)")
                use_katana = False
        else:
            # Try to handle it as a URL missing the protocol
            if '/' in args.input or '.' in args.input:
                url_candidate = 'http://' + args.input
                if ' ' in url_candidate:
                    url_candidate = url_candidate.replace(' ', '%20')
                raw_targets = [url_candidate]
                if args.debug:
                    print(f"[DEBUG] Treating as URL without protocol: {url_candidate}")
                
                # Check for complex URL in direct input with protocol added
                if use_katana and is_complex_url(url_candidate, args.debug):
                    print("\n❌ ERROR: You specified --katana, but a complex URL was provided as input")
                    print("❌ --katana mode only works with simple endpoints (URLs without paths or parameters)")
                    print(f"❌ Complex URL detected: {url_candidate}")
                    
                    print("\nYou have two options:")
                    print("1. Re-run without the --katana flag to send the URL directly to Burp Suite")
                    print("2. Modify your input to only include the hostname (without path or parameters)")
                    
                    choice = prompt_user("\nDo you want to continue without using katana and send the URL directly to Burp Suite? [y/N]: ", False)
                    
                    if choice.lower() != 'y':
                        print("Exiting as requested.")
                        sys.exit(1)
                    
                    # Continue with direct mode (disable katana)
                    print("\n Continuing in direct mode (--katana disabled)")
                    use_katana = False
            else:
                print("❌ Input is neither a valid file nor a recognised target format.")
                sys.exit(1)
    else:
        if sys.stdin.isatty():
            print("❌ No input file, piped XML, or target provided.")
            sys.exit(1)

        raw_input = sys.stdin.read().strip()
        if not raw_input:
            print("❌ No input received via stdin.")
            sys.exit(1)

        if raw_input.startswith("<"):
            if args.debug:
                print("[DEBUG] Treating stdin as XML")
            raw_targets = detect_and_parse_xml(io.BytesIO(raw_input.encode()), args.debug)
        else:
            if args.debug:
                print(f"[DEBUG] Treating stdin as plain text targets:\n{raw_input}")
            lines = raw_input.splitlines()
            raw_targets = parse_plain_text_lines(lines, args.debug)
    
    # Check for complex URLs in input if katana mode is active
    if use_katana and raw_targets:
        complex_urls = contains_complex_urls(raw_targets, args.debug)
        if complex_urls:
            print("\n❌ ERROR: You specified --katana, but complex URLs were detected in the input")
            print("❌ --katana mode only works with simple endpoints (URLs without paths or parameters)")
            print(f"❌ Found {len(complex_urls)} complex URLs")
            
            # Show examples of complex URLs
            print("\nExample complex URLs:")
            for url in complex_urls[:3]:  # Show up to 3 examples
                print(f"  • {url}")
            
            print("\nYou have two options:")
            print("1. Re-run without the --katana flag to send all URLs directly to Burp Suite")
            print("2. Filter your input to only include simple endpoints (domain:port) for use with --katana")
            
            choice = prompt_user("\nDo you want to continue without using katana and send all URLs directly to Burp Suite? [y/N]: ", False)
            
            if choice.lower() != 'y':
                print("Exiting as requested.")
                sys.exit(1)
            
            # Continue with direct mode (disable katana)
            print("\n Continuing in direct mode (--katana disabled)")
            use_katana = False

    if not raw_targets:
        print(" No valid targets found.")
        sys.exit(1)

    print(" Running httpx to verify live services...")
    httpx_targets = run_httpx_filter(raw_targets, args.debug)

    if not httpx_targets:
        print(" No live HTTP/S services detected.")
        sys.exit(1)

    print(f"\n {len(httpx_targets)} valid targets found.\n")
    
    # Get all clean URLs from httpx
    clean_httpx_urls = sanitize_urls(httpx_targets, args.debug)
    
    # Process targets according to the mode (direct or katana)
    if not use_katana:
        # Direct mode - group all URLs by subdomain and process each immediately
        url_groups = group_urls_by_subdomain(clean_httpx_urls, args.debug)
        print(f"\n Found {len(url_groups)} distinct hostnames in httpx output")
        
        # Process each subdomain group
        process_subdomain_groups(url_groups, api_url, args.debug, hailmary)
    else:
        # Katana mode - group URLs first to identify simple endpoints
        simple_targets, _ = group_urls_by_domain(httpx_targets, args.debug)
        
        # Only process simple targets with katana
        print(f"\n Found {len(simple_targets)} simple endpoints (without paths/parameters)")
        print(f"️ Running katana on {len(simple_targets)} simple endpoints...")
        
        for target in simple_targets:
            # Make sure the target URL is sanitized
            target = sanitize_url(target, args.debug)
            
            # When --katana is specified, we automatically run katana without asking
            print(f"\n️ Running katana on {target}...")
            katana_urls = run_katana(target, args.debug)
            
            if not katana_urls:
                print(f"⚠️ Katana found 0 URLs for {target}")
                # Still scan the original URL
                single_url_group = {urlparse(target).netloc: [target]}
                # Process this single target immediately
                process_single_subdomain(urlparse(target).netloc, [target], api_url, args.debug, hailmary)
                continue
            
            print(f"\n Katana found {len(katana_urls)} URLs for {target}")
            
            # Make sure to include the original target URL
            all_urls = [target] + katana_urls
            # Remove any exact duplicates
            all_urls = list(dict.fromkeys(all_urls))
            
            # Group the katana results by subdomain for separate scans
            katana_subdomain_groups = group_urls_by_subdomain(all_urls, args.debug)
            print(f"\n Katana found URLs for {len(katana_subdomain_groups)} different subdomains/hosts")
            
            # Process each subdomain immediately after confirmation
            for subdomain, urls in katana_subdomain_groups.items():
                process_single_subdomain(subdomain, urls, api_url, args.debug, hailmary)

if __name__ == "__main__":
    main()
