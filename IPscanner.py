import socket

print("======================= Ip Scanner ============================\n")

def ip_to_int(ip):
    """Convert IP address to integer for easy comparison"""
    parts = list(map(int, ip.split('.')))
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

def int_to_ip(num):
    """Convert integer back to IP address"""
    return '.'.join([
        str((num >> 24) & 0xFF),
        str((num >> 16) & 0xFF),
        str((num >> 8) & 0xFF),
        str(num & 0xFF)
    ])

def validate_ip(ip):
    """Validate IP address format"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def ipscan(ip_address):
    """Scan a single IP address"""
    try:
        print(f"Scanning {ip_address}", end=" - ")
        hostname = socket.gethostbyaddr(ip_address)
        print(f"UP (Hostname: {hostname[0]})")
    except (socket.herror, socket.gaierror):
        print("DOWN")
    except Exception as e:
        print(f"ERROR: {e}")

def main():
    # Get IP range from user
    ip_s = input("Enter start IP: ").strip()
    ip_e = input("Enter end IP: ").strip()
    
    # Validate IP addresses
    if not validate_ip(ip_s) or not validate_ip(ip_e):
        print("Error: Invalid IP address format")
        return
    
    # Convert to integers for range comparison
    start_ip = ip_to_int(ip_s)
    end_ip = ip_to_int(ip_e)
    
    if start_ip > end_ip:
        print("Error: Start IP must be less than or equal to End IP")
        return
    
    # Calculate total IPs to scan
    total_ips = end_ip - start_ip + 1
    print(f"Scanning range: {ip_s} to {ip_e} ({total_ips} IP addresses)")
    
    # Confirm if range is too large
    if total_ips > 1000:
        response = input(f"This will scan {total_ips} IP addresses. Continue? (y/n): ")
        if response.lower() != 'y':
            print("Scan cancelled")
            return
    
    # Scan all IPs in range
    for ip_int in range(start_ip, end_ip + 1):
        ip_address = int_to_ip(ip_int)
        ipscan(ip_address)

if __name__ == "__main__":
    main()