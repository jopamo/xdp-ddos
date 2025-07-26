import re
from collections import defaultdict
import json
import subprocess
import argparse

# Command-line argument parser
parser = argparse.ArgumentParser(description="Parse kernel logs from journald and generate blocked IP report.")
parser.add_argument('--whois', action='store_true', help="Enable WHOIS lookups for IP ranges (requires 'whois' command installed).")
args = parser.parse_args()

# Fetch current kernel logs from journald (systemd-journal)
# Use journalctl -k -b to get kernel messages from current boot
try:
    journal_output = subprocess.check_output(['journalctl', '-k', '-b']).decode('utf-8').splitlines()
except subprocess.CalledProcessError as e:
    print(f"Error fetching logs from journald: {e}")
    journal_output = []

# Filter only lines containing WAN_INPUT_DROP
log_lines = [line for line in journal_output if 'WAN_INPUT_DROP' in line]

# Regular expression to parse the key fields from each log line in journald format
# Pattern captures journald timestamp (e.g., "Jul 26 10:27:34"), skips hostname and "kernel:", then the fields after "WAN_INPUT_DROP: "
pattern = re.compile(r'^(\w{3} \d{2} \d{2}:\d{2}:\d{2}) \w+ kernel: WAN_INPUT_DROP:\s*(.*)')

# Function to parse a single line into a dictionary
def parse_log_line(line):
    match = pattern.search(line)
    if not match:
        return None

    timestamp = match.group(1)  # Journald timestamp as string
    fields_str = match.group(2)

    # Split the remaining string into key=value pairs
    fields = re.findall(r'(\w+)=([^ ]*)', fields_str)

    parsed = {'timestamp': timestamp}
    for key, value in fields:
        parsed[key.lower()] = value.strip()

    return parsed

# Parse all filtered lines
parsed_logs = [parse_log_line(line) for line in log_lines if parse_log_line(line)]

# Group by source IP for summary (e.g., count attempts per IP)
ip_summary = defaultdict(int)
for log in parsed_logs:
    if 'src' in log:
        ip_summary[log['src']] += 1

# Sort IPs by attempts descending
sorted_ips = sorted(ip_summary.items(), key=lambda x: x[1], reverse=True)

# Function to get the IP range and additional info from WHOIS using subprocess (assumes 'whois' command is installed)
def get_whois_info(ip):
    try:
        output = subprocess.check_output(['whois', ip]).decode('utf-8')

        # Get range (try multiple formats)
        range_str = "Unknown"
        netrange_match = re.search(r'NetRange:\s*([\d\.]+)\s*-\s*([\d\.]+)', output, re.IGNORECASE)
        if netrange_match:
            start, end = netrange_match.groups()
            range_str = f"{start} - {end}"
        elif (cidr_match := re.search(r'CIDR:\s*(.+)', output, re.IGNORECASE)):
            range_str = cidr_match.group(1).strip()
        elif (inetnum_match := re.search(r'inetnum:\s*([\d\.]+)\s*-\s*([\d\.]+)', output, re.IGNORECASE)):
            start, end = inetnum_match.groups()
            range_str = f"{start} - {end}"
        elif (route_match := re.search(r'route:\s*(.+)', output, re.IGNORECASE)):
            range_str = route_match.group(1).strip()

        # Get organization
        org = "Unknown"
        org_match = re.search(r'OrgName:\s*(.+)', output, re.IGNORECASE) or \
                   re.search(r'Organisation:\s*(.+)', output, re.IGNORECASE) or \
                   re.search(r'org-name:\s*(.+)', output, re.IGNORECASE)
        if org_match:
            org = org_match.group(1).strip()

        # Get country
        country = "Unknown"
        country_match = re.search(r'Country:\s*(.+)', output, re.IGNORECASE)
        if country_match:
            country = country_match.group(1).strip()

        return {'range': range_str, 'org': org, 'country': country}
    except Exception as e:
        return {'range': f"Error: {str(e)}", 'org': "Error", 'country': "Error"}

# Get unique IPs
unique_ips = list(ip_summary.keys())

if args.whois:
    # Get WHOIS info for each IP if flag is enabled
    ip_whois = {ip: get_whois_info(ip) for ip in unique_ips}

    # Group IPs by their WHOIS range for aggregated reporting
    range_to_ips = defaultdict(list)
    for ip, info in ip_whois.items():
        range_to_ips[info['range']].append(ip)

    # Sort ranges by total attempts descending
    sorted_ranges = sorted(range_to_ips.items(), key=lambda x: sum(ip_summary[ip] for ip in x[1]), reverse=True)
else:
    # Without WHOIS, treat each IP as its own "range"
    ip_whois = {ip: {'range': ip, 'org': "N/A", 'country': "N/A"} for ip in unique_ips}
    range_to_ips = {ip: [ip] for ip in unique_ips}

    # For no whois, sorted_ranges based on sorted_ips
    sorted_ranges = [(ip, [ip]) for ip, _ in sorted_ips]

# Output parsed data as JSON for easy consumption or further processing
parsed_json = json.dumps(parsed_logs, indent=2)

# Print results
#print("Parsed Logs (JSON):")
#print(parsed_json)

print("\nBlocked IP Range Report (Sorted by Total Attempts Descending):")
for rng, ips in sorted_ranges:
    total_attempts = sum(ip_summary[ip] for ip in ips)
    # Get org and country (assuming same for IPs in same range; take from first IP)
    first_ip = ips[0]
    org = ip_whois[first_ip]['org']
    country = ip_whois[first_ip]['country']

    # Sort IPs within range by attempts descending
    sorted_ips_in_range = sorted(ips, key=lambda ip: ip_summary[ip], reverse=True)

    print("=" * 80)
    print(f"Range: {rng}")
    print(f"Organization: {org}")
    print(f"Country: {country}")
    print(f"Total Attempts: {total_attempts}")
    print("\nIPs in this Range (Sorted by Attempts Descending):")
    print(f"{'IP':<20} {'Attempts':<10}")
    print("-" * 32)
    for ip in sorted_ips_in_range:
        count = ip_summary[ip]
        print(f"{ip:<20} {count:<10}")
    print("=" * 80)
    print()
