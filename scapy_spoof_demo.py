import argparse
from scapy.all import Ether, ICMP, IP, wrpcap


def main():
    parser = argparse.ArgumentParser(description="Scapy spoof packet generator")
    parser.add_argument("--src-ip", default="10.0.0.1")
    parser.add_argument("--dst-ip", default="10.0.0.2")
    parser.add_argument("--src-mac", default="00:11:22:33:44:55")
    parser.add_argument("--dst-mac", default="ff:ff:ff:ff:ff:ff")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--pcap", default="spoof_demo.pcap", help="Output PCAP filename")
    args = parser.parse_args()

    print("\n===================================")
    print(" SCAPY SPOOFED PACKET GENERATION ")
    print("===================================\n")

    packets = []
    for _ in range(args.count):
        pkt = Ether(src=args.src_mac, dst=args.dst_mac) / IP(src=args.src_ip, dst=args.dst_ip) / ICMP()
        packets.append(pkt)

    print(f"Generated {len(packets)} spoofed packet(s)")
    print("\nFirst packet details:\n")
    packets[0].show()
    print("\nPacket summary:")
    print(packets[0].summary())

    wrpcap(args.pcap, packets)
    print(f"\nSaved capture to: {args.pcap}")


if __name__ == "__main__":
    main()
