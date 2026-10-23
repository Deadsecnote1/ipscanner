# IP scanner

A Python 3 lab tool that walks an inclusive IPv4 start-end range and reports whether each host is reachable.

## Usage

Interactive:

```
python3 IPscanner.py
```

Or pass the range on the command line:

```
python3 IPscanner.py 192.168.1.1 192.168.1.254
```

## Behavior

- Accepts dotted IPv4 only; shorthand like `127.1` is rejected.
- Rejects invalid addresses and ranges where start is greater than end.
- Asks for confirmation before scanning more than 1000 addresses.
- Marks a host **UP** or **DOWN** from a single ICMP echo (`ping`). Reverse DNS is used only to show a hostname on live hosts.
- Counts scan failures separately from DOWN in the final summary.

No extra packages are required. ICMP uses the system `ping` command (no raw sockets / no root required).
