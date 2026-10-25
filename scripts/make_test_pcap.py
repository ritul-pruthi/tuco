"""Generate a small synthetic PCAP for local testing. Dev helper."""

import sys
from scapy.all import IP, TCP, wrpcap

TARGET = "10.0.0.50"
SCANNER = "10.0.0.10"
PORT_COUNT = 25
BASE_TS = 1700000000.0


def main(path: str = "/tmp/tuco-test-portscan.pcap") -> None:
    packets = []
    for i in range(PORT_COUNT):
        pkt = IP(src=SCANNER, dst=TARGET) / TCP(
            sport=40000 + i, dport=20 + i, flags="S"
        )
        pkt.time = BASE_TS + i * 0.1
        packets.append(pkt)
    for i in range(3):
        pkt = IP(src=SCANNER, dst="8.8.8.8") / TCP(sport=50000 + i, dport=53, flags="S")
        pkt.time = BASE_TS + 10 + i
        packets.append(pkt)
    wrpcap(path, packets)
    print(f"Wrote {len(packets)} packets to {path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/tuco-test-portscan.pcap")
