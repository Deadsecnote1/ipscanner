import argparse
import ipaddress
import platform
import socket
import subprocess
import sys


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
    """Ping one address and print UP/DOWN/ERROR. Return the result label."""
    print(f"Scanning {ip_address}", end=" - ", flush=True)
    try:
        if host_is_up(ip_address):
            hostname = lookup_hostname(ip_address)
            if hostname:
                print(f"UP (Hostname: {hostname})", flush=True)
            else:
                print("UP", flush=True)
            return "up"
        print("DOWN", flush=True)
        return "down"
    except Exception as e:
        print(f"ERROR: {e}", flush=True)
        return "error"


def parse_cli_args(argv):
    parser = argparse.ArgumentParser(
        description="Scan an inclusive IPv4 start-end range with ICMP ping."
    )
    parser.add_argument("start", nargs="?", help="Start IPv4 address")
    parser.add_argument("end", nargs="?", help="End IPv4 address")
    args = parser.parse_args(argv)
    if (args.start is None) != (args.end is None):
        parser.error("provide both start and end IP addresses, or neither")
    return args.start, args.end


def read_range(start_text, end_text):
    if start_text is None:
        start_text = input("Enter start IP: ").strip()
        end_text = input("Enter end IP: ").strip()

    start_ip = parse_ipv4(start_text)
    end_ip = parse_ipv4(end_text)
    if start_ip is None or end_ip is None:
        print("Error: Invalid IP address format")
        return None
    if start_ip > end_ip:
        print("Error: Start IP must be less than or equal to End IP")
        return None
    return start_ip, end_ip


def main(argv=None):
    start_text, end_text = parse_cli_args(argv)
    print("======================= Ip Scanner ============================\n")

    parsed = read_range(start_text, end_text)
    if parsed is None:
        return 1

    start_ip, end_ip = parsed
    total_ips = int(end_ip) - int(start_ip) + 1
    print(f"Scanning range: {start_ip} to {end_ip} ({total_ips} IP addresses)")

    if total_ips > 1000:
        response = input(f"This will scan {total_ips} IP addresses. Continue? (y/n): ")
        if response.lower() != "y":
            print("Scan cancelled")
            return 0

    up_count = 0
    down_count = 0
    error_count = 0
    for ip in iter_ipv4_range(start_ip, end_ip):
        result = scan_address(str(ip))
        if result == "up":
            up_count += 1
        elif result == "down":
            down_count += 1
        else:
            error_count += 1

    summary = f"Scan complete: {up_count} UP, {down_count} DOWN"
    if error_count:
        summary += f", {error_count} ERROR"
    print(summary)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nScan cancelled")
        sys.exit(130)
