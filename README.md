# IP scanner

A Python 3 lab tool that walks an inclusive IPv4 start-end range and reports whether each host is reachable. You can also scan one TCP port or an inclusive port range.

## Usage

Interactive (prompts for IPs, then an optional port or range):

```
python3 IPscanner.py
```

Pass the IP range on the command line:

```
python3 IPscanner.py 192.168.1.1 192.168.1.254
```

Add a single port or a port range:

```
python3 IPscanner.py 192.168.1.1 192.168.1.254 --ports 80
python3 IPscanner.py 192.168.1.1 192.168.1.254 -p 22-443
```

## Behavior

- Accepts dotted IPv4 only; shorthand like `127.1` is rejected.
- Rejects invalid addresses and ranges where start is greater than end.
- Ports must be between 1 and 65535; a range must be `start-end` with start less than or equal to end.
- Asks for confirmation before scanning more than 1000 addresses, or more than 1000 total TCP connections.
- Marks a host **UP** or **DOWN** from a single ICMP echo (`ping`). Reverse DNS is used only to show a hostname on live hosts.
- When ports are given, each address is also checked with a short TCP connect; results print as `open` or `closed`.
- Counts scan failures separately from DOWN in the final summary.

No extra packages are required. ICMP uses the system `ping` command (no raw sockets / no root required).
