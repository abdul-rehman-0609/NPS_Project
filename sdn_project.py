# =========================================================
# INTERACTIVE SDN SIMULATOR
# Network Layer Attack Detection using SDN
# =========================================================

import time
from collections import defaultdict, deque


# =========================================================
# PACKET
# =========================================================

class Packet:

    def __init__(self, src_ip, dst_ip, src_mac, dst_mac,
                 protocol="ICMP"):

        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.protocol = protocol
        self.timestamp = time.time()


# =========================================================
# HOST
# =========================================================

class Host:

    def __init__(self, name, ip, mac):

        self.name = name
        self.ip = ip
        self.mac = mac

    def send_packet(self, destination):

        return Packet(
            self.ip,
            destination.ip,
            self.mac,
            destination.mac
        )


# =========================================================
# SWITCH
# =========================================================

class Switch:

    def __init__(self, name):

        self.name = name
        self.hosts = []

    def connect(self, host):

        self.hosts.append(host)


# =========================================================
# SDN CONTROLLER
# =========================================================

class SDNController:

    def __init__(self):

        self.ip_mac_table = {}

        self.packet_count = defaultdict(int)

        self.packet_log = defaultdict(deque)

        self.TIME_WINDOW = 5

        self.DOS_THRESHOLD = 25

        self.total_packets = 0

        self.total_alerts = 0

        self.blocked_ips = set()

        print("\nSDN Controller Started")
        print("Centralized Monitoring Enabled")

    # =====================================================
    # PROCESS PACKET
    # =====================================================

    def process_packet(self, packet):

        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        src_mac = packet.src_mac

        self.total_packets += 1

        # =================================================
        # BLOCKED HOST CHECK
        # =================================================

        if src_ip in self.blocked_ips:

            print(f"BLOCKED TRAFFIC FROM {src_ip}")
            return

        # =================================================
        # IP SPOOF DETECTION
        # =================================================

        if src_ip in self.ip_mac_table:

            if self.ip_mac_table[src_ip] != src_mac:

                self.total_alerts += 1

                print("\nALERT: IP SPOOFING DETECTED")
                print(f"Fake IP : {src_ip}")
                print(f"Real MAC: {self.ip_mac_table[src_ip]}")
                print(f"Fake MAC: {src_mac}")

                return

        else:
            self.ip_mac_table[src_ip] = src_mac

        # =================================================
        # DOS DETECTION
        # =================================================

        now = time.time()

        q = self.packet_log[src_ip]

        q.append(now)

        while q and now - q[0] > self.TIME_WINDOW:
            q.popleft()

        if len(q) > self.DOS_THRESHOLD:

            self.total_alerts += 1

            print("\nALERT: DOS ATTACK DETECTED")
            print(f"Attacker : {src_ip}")
            print(f"Packets  : {len(q)}")
            print("Action   : Host Automatically Blocked")

            self.blocked_ips.add(src_ip)

            return

        # =================================================
        # NORMAL TRAFFIC
        # =================================================

        self.packet_count[src_ip] += 1

        print(f"Packet Forwarded: {src_ip} → {dst_ip}")

    # =====================================================
    # SHOW STATS
    # =====================================================

    def show_statistics(self):

        print("\n================================================")
        print("                 NETWORK STATISTICS")
        print("================================================")

        print(f"Total Packets : {self.total_packets}")
        print(f"Total Alerts  : {self.total_alerts}")

        print("\nHost Traffic:")

        if len(self.packet_count) == 0:
            print("No traffic yet")

        for ip, count in self.packet_count.items():
            print(f"{ip} --> {count} packets")

        print("\nBlocked Hosts:")

        if len(self.blocked_ips) == 0:
            print("None")
        else:
            for ip in self.blocked_ips:
                print(ip)

        print("\nKnown IP-MAC Table:")

        for ip, mac in self.ip_mac_table.items():
            print(f"{ip} --> {mac}")

        print("================================================\n")


# =========================================================
# NETWORK TOPOLOGY
# =========================================================

class Network:

    def __init__(self):

        self.switch = Switch("s1")

        self.hosts = {
            "h1": Host("h1", "10.0.0.1", "00:00:00:00:00:01"),
            "h2": Host("h2", "10.0.0.2", "00:00:00:00:00:02"),
            "h3": Host("h3", "10.0.0.3", "00:00:00:00:00:03")
        }

        for host in self.hosts.values():
            self.switch.connect(host)

        self.controller = SDNController()

        self.show_topology()

    # =====================================================
    # SHOW TOPOLOGY
    # =====================================================

    def show_topology(self):

        print("\n================ TOPOLOGY ================")

        print("""
                   h1
                    |
                    |
            h2 ---- s1 ---- h3
        """)

        print("==========================================")

        print("\nHosts:")

        for host in self.hosts.values():
            print(f"{host.name} --> {host.ip}")

    # =====================================================
    # NORMAL PING
    # =====================================================

    def ping(self, src_name, dst_name):

        if src_name not in self.hosts or dst_name not in self.hosts:
            print("Invalid host!")
            return

        src = self.hosts[src_name]
        dst = self.hosts[dst_name]

        print(f"\nPING {dst.ip} from {src.ip}\n")

        for i in range(4):

            packet = src.send_packet(dst)

            self.controller.process_packet(packet)

            print(f"64 bytes from {dst.ip}: icmp_seq={i+1}")

            time.sleep(1)

        print("\nPing Completed Successfully")

    # =====================================================
    # DOS ATTACK
    # =====================================================

    def flood_ping(self, src_name, dst_name):

        if src_name not in self.hosts or dst_name not in self.hosts:
            print("Invalid host!")
            return

        src = self.hosts[src_name]
        dst = self.hosts[dst_name]

        print("\nFLOOD ATTACK STARTED")
        print(f"Attacker: {src.ip}")
        print(f"Victim  : {dst.ip}\n")

        for i in range(60):

            packet = src.send_packet(dst)

            self.controller.process_packet(packet)

            time.sleep(0.05)

        print("\nFlood Attack Finished")

    # =====================================================
    # PING ALL
    # =====================================================

    def ping_all(self):

        host_names = list(self.hosts.keys())

        for src in host_names:
            for dst in host_names:
                if src != dst:
                    self.ping(src, dst)

    # =====================================================
    # IP SPOOFING ATTACK
    # =====================================================

    def spoof_attack(self, victim_ip, attacker_host):

        if attacker_host not in self.hosts:
            print("Invalid attacker host!")
            return

        attacker = self.hosts[attacker_host]

        print("\n================================================")
        print("          IP SPOOFING ATTACK SIMULATION")
        print("================================================")

        print("\nSTEP 1: Controller learns legitimate mapping")

        legit_packet = Packet(
            src_ip=victim_ip,
            dst_ip="10.0.0.2",
            src_mac="00:00:00:00:00:01",
            dst_mac="00:00:00:00:00:02"
        )

        self.controller.process_packet(legit_packet)

        time.sleep(2)

        print("\nSTEP 2: Attacker impersonates victim IP")

        print(f"\nAttacker Host : {attacker.name}")
        print(f"Fake IP Used  : {victim_ip}")
        print(f"Fake MAC Used : {attacker.mac}")

        spoofed_packet = Packet(
            src_ip=victim_ip,
            dst_ip="10.0.0.2",
            src_mac=attacker.mac,
            dst_mac="00:00:00:00:00:02"
        )

        time.sleep(2)

        print("\nSTEP 3: Controller analyzing packet...\n")

        time.sleep(2)

        self.controller.process_packet(spoofed_packet)

        print("\n================================================")

    # =====================================================
    # COMMAND INTERPRETER
    # =====================================================

    def execute_command(self, command):

        parts = command.strip().split()

        # =================================================
        # HELP
        # =================================================

        if command == "help":

            print("""
================ AVAILABLE COMMANDS ================

NORMAL TRAFFIC:
h1 ping h2
h2 ping h3
pingall

DOS ATTACK:
h1 ping -f h2

IP SPOOFING:
spoof 10.0.0.1 h3

SHOW STATS:
stats

SHOW TOPOLOGY:
topo

EXIT:
exit
====================================================
            """)

            return

        # =================================================
        # TOPOLOGY
        # =================================================

        if command == "topo":
            self.show_topology()
            return

        # =================================================
        # STATS
        # =================================================

        if command == "stats":
            self.controller.show_statistics()
            return

        # =================================================
        # PINGALL
        # =================================================

        if command == "pingall":
            self.ping_all()
            return

        # =================================================
        # SPOOF COMMAND
        # =================================================

        if len(parts) == 3 and parts[0] == "spoof":

            victim_ip = parts[1]
            attacker = parts[2]

            self.spoof_attack(victim_ip, attacker)
            return

        # =================================================
        # NORMAL PING
        # =================================================

        if len(parts) == 3:

            src = parts[0]
            action = parts[1]
            dst = parts[2]

            if action == "ping":
                self.ping(src, dst)
                return

        # =================================================
        # FLOOD PING
        # =================================================

        if len(parts) == 4:

            src = parts[0]
            action = parts[1]
            flag = parts[2]
            dst = parts[3]

            if action == "ping" and flag == "-f":
                self.flood_ping(src, dst)
                return

        print("Invalid command!")
        print("Type 'help' to see available commands")


# =========================================================
# MAIN APPLICATION
# =========================================================

print("""
=========================================================
        NETWORK LAYER ATTACK DETECTION USING SDN
=========================================================

Custom Lightweight SDN Controller
Inspired by Ryu + Mininet Architecture

Features:

✔ Interactive CLI
✔ SDN-style centralized controller
✔ Virtual network topology
✔ Normal ICMP traffic simulation
✔ DoS attack detection
✔ IP spoofing detection
✔ Automatic host blocking
✔ Real-time statistics

Type 'help' to begin.
=========================================================
""")

network = Network()

while True:

    try:

        command = input("\nmininet> ")

        if command == "exit":

            print("\nShutting Down SDN Simulator...")
            break

        network.execute_command(command)

    except KeyboardInterrupt:

        print("\n\nSDN Simulator Terminated")
        break
