import ipaddress
import platform
import socket
import subprocess
import sys

print("======================= Ip Scanner ============================\n")


def parse_ipv4(ip):
    """Parse a dotted IPv4 address, rejecting shorthand forms."""
    try:
        return ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return None


def iter_ipv4_range(start_ip, end_ip):
    """Yield each IPv4Address from start to end, inclusive."""
    for num in range(int(start_ip), int(end_ip) + 1):
        yield ipaddress.IPv4Address(num)


def host_is_up(ip_address):
    """Return True if the host answers a single ICMP echo."""
    if platform.system().lower() == "windows":
        ping_cmd = ["ping", "-n", "1", "-w", "1000", ip_address]
    else:
        ping_cmd = ["ping", "-c", "1", "-W", "1", ip_address]

    result = subprocess.run(
        ping_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def lookup_hostname(ip_address):
    """Return a reverse-DNS name if one exists, otherwise None."""
    try:
        hostname, _aliases, _addrs = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def scan_address(ip_address):
    """Ping one address and print UP/DOWN, with hostname when available."""
    print(f"Scanning {ip_address}", end=" - ", flush=True)
    try:
        if host_is_up(ip_address):
            hostname = lookup_hostname(ip_address)
            if hostname:
                print(f"UP (Hostname: {hostname})", flush=True)
            else:
                print("UP", flush=True)
            return True
        print("DOWN", flush=True)
        return False
    except Exception as e:
        print(f"ERROR: {e}", flush=True)
        return False


def main():
    ip_s = input("Enter start IP: ").strip()
    ip_e = input("Enter end IP: ").strip()

    start_ip = parse_ipv4(ip_s)
    end_ip = parse_ipv4(ip_e)
    if start_ip is None or end_ip is None:
        print("Error: Invalid IP address format")
        return

    if start_ip > end_ip:
        print("Error: Start IP must be less than or equal to End IP")
        return

    total_ips = int(end_ip) - int(start_ip) + 1
    print(f"Scanning range: {start_ip} to {end_ip} ({total_ips} IP addresses)")

    if total_ips > 1000:
        response = input(f"This will scan {total_ips} IP addresses. Continue? (y/n): ")
        if response.lower() != "y":
            print("Scan cancelled")
            return

    up_count = 0
    down_count = 0
    for ip in iter_ipv4_range(start_ip, end_ip):
        if scan_address(str(ip)):
            up_count += 1
        else:
            down_count += 1

    print(f"Scan complete: {up_count} UP, {down_count} DOWN")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan cancelled")
        sys.exit(130)
