"""Send one DHCPDISCOVER from a chosen MAC (a rogue device asking the network for an address).

Pure standard library, needs root (UDP port 68). Usage: dhcp_discover.py <mac> [hostname]
"""
from __future__ import annotations

import os
import socket
import sys

MAGIC = bytes([99, 130, 83, 99])


def build_discover(mac: str, hostname: str = "rogue-demo", xid: int | None = None) -> bytes:
    hw = bytes(int(part, 16) for part in mac.split(":"))
    if len(hw) != 6:
        raise ValueError("MAC must have six octets")
    xid = int.from_bytes(os.urandom(4), "big") if xid is None else xid
    name = hostname.encode("ascii", "ignore")[:63]
    packet = bytes([1, 1, 6, 0]) + xid.to_bytes(4, "big")      # BOOTREQUEST, ethernet, hlen 6
    packet += bytes(2) + (0x8000).to_bytes(2, "big")           # secs, flags = broadcast
    packet += bytes(16)                                        # ciaddr yiaddr siaddr giaddr
    packet += hw + bytes(10) + bytes(64) + bytes(128)          # chaddr (16), sname, file
    packet += MAGIC
    packet += bytes([53, 1, 1])                                # option 53: DHCPDISCOVER
    packet += bytes([12, len(name)]) + name                    # option 12: hostname
    packet += bytes([55, 3, 1, 3, 6])                          # option 55: parameter request list
    return packet + bytes([255])


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    packet = build_discover(argv[1], argv[2] if len(argv) > 2 else "rogue-demo")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 68))
        sock.sendto(packet, ("255.255.255.255", 67))
    print(f"sent DHCPDISCOVER as {argv[1]} ({len(packet)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
