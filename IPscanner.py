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


def parse_ports(text):
    """Parse a single port or inclusive range like 80 or 22-443."""
    text = text.strip()
    if not text:
        raise ValueError("port or range is empty")

    if "-" in text:
        start_text, sep, end_text = text.partition("-")
        if not sep or "-" in end_text or not start_text or not end_text:
            raise ValueError("port range must look like 22-443")
        start_port = _parse_one_port(start_text)
        end_port = _parse_one_port(end_text)
        if start_port > end_port:
            raise ValueError("start port must be less than or equal to end port")
        return list(range(start_port, end_port + 1))

    return [_parse_one_port(text)]


def _parse_one_port(text):
    try:
        port = int(text.strip())
    except ValueError:
        raise ValueError(f"invalid port: {text.strip()!r}") from None
    if port < 1 or port > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return port


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


def port_is_open(ip_address, port, timeout=0.5):
    """Return True if a TCP connect to ip:port succeeds."""
    try:
        with socket.create_connection((ip_address, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def scan_address(ip_address, ports=None):
    """Ping one address, optionally scan TCP ports, and print the result."""
    print(f"Scanning {ip_address}", end=" - ", flush=True)
    try:
        if host_is_up(ip_address):
            hostname = lookup_hostname(ip_address)
            if hostname:
                print(f"UP (Hostname: {hostname})", flush=True)
            else:
                print("UP", flush=True)
            host_result = "up"
        else:
            print("DOWN", flush=True)
            host_result = "down"
    except Exception as e:
        print(f"ERROR: {e}", flush=True)
        return "error", 0, 0

    open_count = 0
    closed_count = 0
    if ports:
        for port in ports:
            if port_is_open(ip_address, port):
                print(f"  {port}/tcp open", flush=True)
                open_count += 1
            else:
                print(f"  {port}/tcp closed", flush=True)
                closed_count += 1

    return host_result, open_count, closed_count


def parse_cli_args(argv):
    parser = argparse.ArgumentParser(
        description="Scan an inclusive IPv4 start-end range with ICMP ping "
        "and optional TCP ports."
    )
    parser.add_argument("start", nargs="?", help="Start IPv4 address")
    parser.add_argument("end", nargs="?", help="End IPv4 address")
    parser.add_argument(
        "-p",
        "--ports",
        metavar="PORT",
        help="TCP port or inclusive range, for example 80 or 22-443",
    )
    args = parser.parse_args(argv)
    if (args.start is None) != (args.end is None):
        parser.error("provide both start and end IP addresses, or neither")
    return args


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


def read_ports(ports_text, prompt_if_missing):
    if ports_text is None and prompt_if_missing:
        ports_text = input(
            "Enter port or range (blank to skip): "
        ).strip()
        if not ports_text:
            return []

    if not ports_text:
        return []

    try:
        return parse_ports(ports_text)
    except ValueError as e:
        print(f"Error: {e}")
        return None


def main(argv=None):
    args = parse_cli_args(argv)
    print("======================= Ip Scanner ============================\n")

    parsed = read_range(args.start, args.end)
    if parsed is None:
        return 1

    start_ip, end_ip = parsed
    ports = read_ports(args.ports, prompt_if_missing=args.start is None)
    if ports is None:
        return 1

    total_ips = int(end_ip) - int(start_ip) + 1
    range_line = f"Scanning range: {start_ip} to {end_ip} ({total_ips} IP addresses)"
    if ports:
        if len(ports) == 1:
            range_line += f", port {ports[0]}"
        else:
            range_line += f", ports {ports[0]}-{ports[-1]} ({len(ports)} ports)"
    print(range_line)

    total_probes = total_ips * (len(ports) if ports else 1)
    if total_ips > 1000 or (ports and total_probes > 1000):
        if ports:
            prompt = (
                f"This will scan {total_ips} IP addresses and {len(ports)} "
                f"TCP ports ({total_probes} connections). Continue? (y/n): "
            )
        else:
            prompt = f"This will scan {total_ips} IP addresses. Continue? (y/n): "
        response = input(prompt)
        if response.lower() != "y":
            print("Scan cancelled")
            return 0

    up_count = 0
    down_count = 0
    error_count = 0
    open_count = 0
    closed_count = 0
    for ip in iter_ipv4_range(start_ip, end_ip):
        result, host_open, host_closed = scan_address(str(ip), ports)
        open_count += host_open
        closed_count += host_closed
        if result == "up":
            up_count += 1
        elif result == "down":
            down_count += 1
        else:
            error_count += 1

    summary = f"Scan complete: {up_count} UP, {down_count} DOWN"
    if error_count:
        summary += f", {error_count} ERROR"
    if ports:
        summary += f"; {open_count} open, {closed_count} closed"
    print(summary)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nScan cancelled")
        sys.exit(130)
