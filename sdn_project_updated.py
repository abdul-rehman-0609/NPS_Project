# =========================================================
# INTERACTIVE SDN SIMULATOR 
# Network Layer Attack Detection using SDN
# =========================================================

import time
import threading
import sys
import math
import tkinter as tk
from collections import defaultdict, deque


# =========================================================
# COLOUR PALETTE
# =========================================================
C = {
    'bg':       '#080d18',
    'panel':    '#0d1526',
    'card':     '#0f1c30',
    'border':   '#1a3050',
    'accent':   '#00e5ff',
    'green':    '#00ff88',
    'red':      '#ff3060',
    'yellow':   '#ffd700',
    'orange':   '#ff8c00',
    'text':     '#c8d8f0',
    'muted':    '#3a5070',
    'heading':  '#ffffff',
    'hdr_bg':   '#050a14',
}


# =========================================================
# PACKET  
# =========================================================
class Packet:

    def __init__(self, src_ip, dst_ip, src_mac, dst_mac,
                 protocol="ICMP"):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_mac  = src_mac
        self.dst_mac  = dst_mac
        self.protocol = protocol
        self.timestamp = time.time()


# =========================================================
# HOST  
# =========================================================
class Host:

    def __init__(self, name, ip, mac):
        self.name = name
        self.ip   = ip
        self.mac  = mac

    def send_packet(self, destination):
        return Packet(
            self.ip,   destination.ip,
            self.mac,  destination.mac
        )


# =========================================================
# SWITCH  
# =========================================================
class Switch:

    def __init__(self, name):
        self.name  = name
        self.hosts = []

    def connect(self, host):
        self.hosts.append(host)


# =========================================================
# SDN CONTROLLER  
# =========================================================
class SDNController:

    def __init__(self):
        self.ip_mac_table   = {}
        self.packet_count   = defaultdict(int)
        self.packet_log     = defaultdict(deque)
        self.TIME_WINDOW    = 5
        self.DOS_THRESHOLD  = 25
        self.total_packets  = 0
        self.total_alerts   = 0
        self.blocked_ips    = set()

        print("\n🔥 SDN Controller Started")
        print("Centralized Monitoring Enabled")

    # --------------------------------------------------
    def process_packet(self, packet):

        src_ip  = packet.src_ip
        dst_ip  = packet.dst_ip
        src_mac = packet.src_mac

        self.total_packets += 1

        # ---------- blocked check ----------
        if src_ip in self.blocked_ips:
            print(f"🚫 BLOCKED TRAFFIC FROM {src_ip}")
            return

        # ---------- IP spoof detection ----------
        if src_ip in self.ip_mac_table:
            if self.ip_mac_table[src_ip] != src_mac:
                self.total_alerts += 1
                print("\n🚨 ALERT: IP SPOOFING DETECTED")
                print(f"Fake IP : {src_ip}")
                print(f"Real MAC: {self.ip_mac_table[src_ip]}")
                print(f"Fake MAC: {src_mac}")
                return
        else:
            self.ip_mac_table[src_ip] = src_mac

        # ---------- DoS detection ----------
        now = time.time()
        q   = self.packet_log[src_ip]
        q.append(now)
        while q and now - q[0] > self.TIME_WINDOW:
            q.popleft()

        if len(q) > self.DOS_THRESHOLD:
            self.total_alerts += 1
            print("\n🚨 ALERT: DOS ATTACK DETECTED")
            print(f"Attacker : {src_ip}")
            print(f"Packets  : {len(q)}")
            print("Action   : Host Automatically Blocked")
            self.blocked_ips.add(src_ip)
            return

        # ---------- normal ----------
        self.packet_count[src_ip] += 1
        print(f"📦 Packet Forwarded: {src_ip} → {dst_ip}")

    # --------------------------------------------------
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
            print(f"  {ip} --> {count} packets")
        print("\nBlocked Hosts:")
        if len(self.blocked_ips) == 0:
            print("  None")
        else:
            for ip in self.blocked_ips:
                print(f"  {ip}")
        print("\nKnown IP-MAC Table:")
        for ip, mac in self.ip_mac_table.items():
            print(f"  {ip} --> {mac}")
        print("================================================\n")


# =========================================================
# NETWORK TOPOLOGY  
# =========================================================
class Network:

    def __init__(self):
        self.switch = Switch("s1")
        self.hosts  = {
            "h1": Host("h1", "10.0.0.1", "00:00:00:00:00:01"),
            "h2": Host("h2", "10.0.0.2", "00:00:00:00:00:02"),
            "h3": Host("h3", "10.0.0.3", "00:00:00:00:00:03"),
        }
        for host in self.hosts.values():
            self.switch.connect(host)
        self.controller = SDNController()
        self.show_topology()

    # --------------------------------------------------
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
            print(f"  {host.name} --> {host.ip}")

    # --------------------------------------------------
    def ping(self, src_name, dst_name):
        if src_name not in self.hosts or dst_name not in self.hosts:
            print("❌ Invalid host")
            return
        src = self.hosts[src_name]
        dst = self.hosts[dst_name]
        print(f"\nPING {dst.ip} from {src.ip}\n")
        for i in range(4):
            packet = src.send_packet(dst)
            self.controller.process_packet(packet)
            print(f"  64 bytes from {dst.ip}: icmp_seq={i+1}")
            time.sleep(1)
        print("\nPing Completed Successfully")

    # --------------------------------------------------
    def flood_ping(self, src_name, dst_name):
        if src_name not in self.hosts or dst_name not in self.hosts:
            print("❌ Invalid host")
            return
        src = self.hosts[src_name]
        dst = self.hosts[dst_name]
        print("\n🔥 FLOOD ATTACK STARTED")
        print(f"Attacker: {src.ip}")
        print(f"Victim  : {dst.ip}\n")
        for i in range(60):
            packet = src.send_packet(dst)
            self.controller.process_packet(packet)
            time.sleep(0.05)
        print("\nFlood Attack Finished")

    # --------------------------------------------------
    def spoof_attack(self, victim_ip, attacker_host):
        if attacker_host not in self.hosts:
            print("❌ Invalid attacker host")
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
            dst_mac="00:00:00:00:00:02",
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
            dst_mac="00:00:00:00:00:02",
        )
        time.sleep(2)
        print("\nSTEP 3: Controller analyzing packet...\n")
        time.sleep(2)
        self.controller.process_packet(spoofed_packet)
        print("\n================================================")

    # --------------------------------------------------
    def execute_command(self, command):
        parts = command.strip().split()
        if command == "help":
            print("""
================ AVAILABLE COMMANDS ================
NORMAL TRAFFIC : h1 ping h2  |  h2 ping h3
DOS ATTACK     : h1 ping -f h2
IP SPOOFING    : spoof 10.0.0.1 h3
SHOW STATS     : stats
SHOW TOPOLOGY  : topo
EXIT           : exit
====================================================
            """)
            return
        if command == "topo":
            self.show_topology()
            return
        if command == "stats":
            self.controller.show_statistics()
            return
        if len(parts) == 3 and parts[0] == "spoof":
            self.spoof_attack(parts[1], parts[2])
            return
        if len(parts) == 3:
            src, action, dst = parts
            if action == "ping":
                self.ping(src, dst)
                return
        if len(parts) == 4:
            src, action, flag, dst = parts
            if action == "ping" and flag == "-f":
                self.flood_ping(src, dst)
                return
        print("❌ Invalid command — type 'help' to see available commands")


# =========================================================
# STDOUT REDIRECT
# =========================================================
class _StdoutRedirect:
    """Captures every print() and forwards it to the GUI."""

    def __init__(self, callback):
        self._cb   = callback
        self._orig = sys.__stdout__

    def write(self, text):
        if text:
            self._cb(text)

    def flush(self):
        pass


# =========================================================
# GUI APPLICATION
# =========================================================
class SDNSimulatorGUI:

    # IP → host-node mapping
    _IP_HOST = {
        "10.0.0.1": "h1",
        "10.0.0.2": "h2",
        "10.0.0.3": "h3",
    }

    # --------------------------------------------------
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SDN Attack Detector — Network Layer Security")
        self.root.configure(bg=C['bg'])
        self.root.geometry("1300x840")
        self.root.minsize(1100, 720)

        self._busy          = False
        self.network        = None

        # canvas state
        self.node_pos   = {}
        self.node_oval  = {}
        self.node_color = {}

        # live counters
        self._v_packets  = tk.IntVar(value=0)
        self._v_alerts   = tk.IntVar(value=0)
        self._v_blocked  = tk.IntVar(value=0)
        self._v_status   = tk.StringVar(value="Initialising …")

        self._build_ui()

        # redirect stdout BEFORE Network() so startup prints appear
        sys.stdout = _StdoutRedirect(self._on_print)

        self.network = Network()

        self._v_status.set("Ready — select an action from the left panel")
        self._tick_stats()

    # ==================================================
    # UI CONSTRUCTION
    # ==================================================
    def _build_ui(self):
        self._build_header()
        body = tk.Frame(self.root, bg=C['bg'])
        body.pack(fill='both', expand=True, padx=8, pady=(4, 4))
        self._build_left(body)
        self._build_right(body)
        self._build_statusbar()

    # --------------------------------------------------
    def _build_header(self):
        hdr = tk.Frame(self.root, bg=C['hdr_bg'], height=58)
        hdr.pack(fill='x')
        hdr.pack_propagate(False)

        tk.Label(
            hdr, text="⬡  SDN ATTACK DETECTOR",
            bg=C['hdr_bg'], fg=C['accent'],
            font=('Courier New', 17, 'bold')
        ).pack(side='left', padx=20)

        tk.Label(
            hdr, text="Network Layer Security Simulator",
            bg=C['hdr_bg'], fg=C['muted'],
            font=('Courier New', 9)
        ).pack(side='left', padx=0)

        # Counter widgets
        for label, var, color in (
            ("PACKETS",  self._v_packets, C['green']),
            ("ALERTS",   self._v_alerts,  C['red']),
            ("BLOCKED",  self._v_blocked, C['yellow']),
        ):
            box = tk.Frame(hdr, bg=C['hdr_bg'])
            box.pack(side='right', padx=18, pady=6)
            tk.Label(box, text=label, bg=C['hdr_bg'], fg=C['muted'],
                     font=('Courier New', 8, 'bold')).pack()
            tk.Label(box, textvariable=var, bg=C['hdr_bg'], fg=color,
                     font=('Courier New', 22, 'bold')).pack()

    # --------------------------------------------------
    def _build_statusbar(self):
        sb = tk.Frame(self.root, bg=C['hdr_bg'], height=26)
        sb.pack(fill='x', side='bottom')
        sb.pack_propagate(False)
        tk.Label(sb, textvariable=self._v_status,
                 bg=C['hdr_bg'], fg=C['muted'],
                 font=('Courier New', 9)).pack(side='left', padx=14)

    # --------------------------------------------------
    def _build_left(self, parent):
        frame = tk.Frame(parent, bg=C['panel'], width=290,
                         highlightbackground=C['border'],
                         highlightthickness=1)
        frame.pack(side='left', fill='y', padx=(0, 8))
        frame.pack_propagate(False)

        # ── Normal Traffic ──────────────────────────────
        self._section(frame, "NORMAL TRAFFIC")
        for s, d in [("h1","h2"), ("h2","h3"), ("h1","h3"), ("h3","h2")]:
            self._btn(frame, f"  {s}  →  {d}   ping",
                      lambda s=s,d=d: self._run(f"{s} ping {d}"),
                      C['green'])

        # ── DoS Attack ──────────────────────────────────
        self._section(frame, "DOS ATTACK")
        for s, d in [("h1","h2"), ("h2","h3"), ("h3","h1")]:
            self._btn(frame, f"  {s} floods {d}",
                      lambda s=s,d=d: self._run(f"{s} ping -f {d}"),
                      C['red'])

        # ── IP Spoofing ─────────────────────────────────
        self._section(frame, "IP SPOOFING")
        for vic_ip, att in [("10.0.0.1","h3"),("10.0.0.2","h1"),("10.0.0.3","h2")]:
            vic = self._IP_HOST[vic_ip]
            self._btn(frame, f"  {att} spoofs {vic}",
                      lambda v=vic_ip,a=att: self._run(f"spoof {v} {a}"),
                      C['orange'])

        # ── Utilities ───────────────────────────────────
        self._section(frame, "UTILITIES")
        self._btn(frame, "  Show Statistics",
                  lambda: self._run("stats"), C['accent'])
        self._btn(frame, "  Show Topology",
                  lambda: self._run("topo"), C['accent'])
        self._btn(frame, "  Clear Log",
                  self._clear_log, C['muted'])

        # ── How-to Guide ────────────────────────────────
        self._section(frame, "HOW TO USE")
        guide_txt = (
            "① NORMAL PING\n"
            "Click any ping button to send\n"
            "4 ICMP packets. Packets show\n"
            "as green in the log + animated\n"
            "on the topology canvas.\n\n"

            "② DETECT DOS ATTACK\n"
            "Click any 'floods' button. 60\n"
            "rapid packets are sent. Once\n"
            ">25 packets hit in 5 seconds\n"
            "the 🚨 DoS alert fires and the\n"
            "attacker is auto-blocked (red).\n\n"

            "③ DETECT IP SPOOFING\n"
            "Click any 'spoofs' button. A\n"
            "host sends traffic with a fake\n"
            "IP. The controller checks its\n"
            "IP→MAC table and raises the\n"
            "🚨 Spoofing alert (orange).\n\n"

            "④ STATS\n"
            "See per-host packet counts,\n"
            "alerts, and blocked host list.\n\n"

            "Watch the TOPOLOGY CANVAS for\n"
            "live animated packet flows and\n"
            "node colour changes!"
        )
        lbl = tk.Label(
            frame, text=guide_txt,
            bg=C['card'], fg=C['text'],
            font=('Courier New', 8),
            justify='left', anchor='nw',
            padx=10, pady=10,
        )
        lbl.pack(fill='x', padx=8, pady=(0, 10))

    # --------------------------------------------------
    def _build_right(self, parent):
        right = tk.Frame(parent, bg=C['bg'])
        right.pack(side='left', fill='both', expand=True)

        # ── Topology canvas ──────────────────────────────
        topo_outer = tk.Frame(right, bg=C['panel'],
                              highlightbackground=C['border'],
                              highlightthickness=1)
        topo_outer.pack(fill='x', pady=(0, 8))

        hdr = tk.Frame(topo_outer, bg=C['panel'])
        hdr.pack(fill='x', padx=12, pady=(8, 0))
        tk.Label(hdr, text="NETWORK TOPOLOGY",
                 bg=C['panel'], fg=C['muted'],
                 font=('Courier New', 9, 'bold')).pack(side='left')
        self._legend(hdr)

        self.canvas = tk.Canvas(
            topo_outer, bg=C['panel'],
            height=230, highlightthickness=0,
        )
        self.canvas.pack(fill='x', padx=12, pady=8)
        self.canvas.bind('<Configure>', lambda e: self._draw_topology())

        # ── Activity log ─────────────────────────────────
        log_outer = tk.Frame(right, bg=C['panel'],
                             highlightbackground=C['border'],
                             highlightthickness=1)
        log_outer.pack(fill='both', expand=True)

        log_hdr = tk.Frame(log_outer, bg=C['panel'])
        log_hdr.pack(fill='x', padx=12, pady=(8, 0))
        tk.Label(log_hdr, text="ACTIVITY LOG",
                 bg=C['panel'], fg=C['muted'],
                 font=('Courier New', 9, 'bold')).pack(side='left')

        self.log = tk.Text(
            log_outer,
            bg=C['card'], fg=C['text'],
            font=('Courier New', 10),
            relief='flat', padx=14, pady=8,
            state='disabled', wrap='word',
            insertbackground=C['accent'],
            selectbackground=C['border'],
        )
        self.log.pack(fill='both', expand=True, padx=8, pady=8)

        vsb = tk.Scrollbar(self.log, command=self.log.yview,
                           bg=C['panel'], troughcolor=C['card'],
                           relief='flat')
        vsb.pack(side='right', fill='y')
        self.log.configure(yscrollcommand=vsb.set)

        # colour tags
        self.log.tag_config('normal',   foreground=C['green'])
        self.log.tag_config('alert',    foreground=C['red'])
        self.log.tag_config('spoof',    foreground=C['orange'])
        self.log.tag_config('blocked',  foreground=C['yellow'])
        self.log.tag_config('info',     foreground=C['accent'])
        self.log.tag_config('muted',    foreground=C['muted'])
        self.log.tag_config('default',  foreground=C['text'])
        self.log.tag_config('ts',       foreground='#2a4060')

    # --------------------------------------------------
    def _legend(self, parent):
        for color, label in (
            (C['green'],  "Normal"),
            (C['red'],    "DoS"),
            (C['orange'], "Spoof"),
            (C['yellow'], "Blocked"),
        ):
            dot = tk.Canvas(parent, width=10, height=10,
                            bg=C['panel'], highlightthickness=0)
            dot.create_oval(1, 1, 9, 9, fill=color, outline='')
            dot.pack(side='right', padx=(4, 0))
            tk.Label(parent, text=label, bg=C['panel'],
                     fg=C['muted'], font=('Courier New', 8)).pack(side='right')

    # --------------------------------------------------
    def _section(self, parent, text):
        f = tk.Frame(parent, bg=C['panel'])
        f.pack(fill='x', padx=8, pady=(10, 2))
        tk.Frame(f, bg=C['border'], height=1).pack(fill='x', pady=(0, 4))
        tk.Label(f, text=text, bg=C['panel'], fg=C['muted'],
                 font=('Courier New', 8, 'bold')).pack(anchor='w')

    # --------------------------------------------------
    def _btn(self, parent, text, cmd, color):
        b = tk.Button(
            parent, text=text,
            bg=C['card'], fg=color,
            activebackground=color, activeforeground=C['bg'],
            font=('Courier New', 9, 'bold'),
            relief='flat', cursor='hand2',
            bd=0, pady=7,
            command=cmd,
        )
        b.pack(fill='x', padx=8, pady=2)
        b.bind('<Enter>', lambda e: b.config(bg=C['border']))
        b.bind('<Leave>', lambda e: b.config(bg=C['card']))

    # ==================================================
    # TOPOLOGY CANVAS
    # ==================================================
    def _draw_topology(self):
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w <= 1:
            self.root.after(80, self._draw_topology)
            return

        self.canvas.delete('all')
        cx, cy   = w // 2, h // 2
        rad      = min(w, h) * 0.30

        # node positions: h1 top, h2 lower-left, h3 lower-right, s1 centre
        self.node_pos = {
            's1': (cx,                   cy),
            'h1': (cx,                   cy - rad),
            'h2': (int(cx - rad * 0.95), int(cy + rad * 0.55)),
            'h3': (int(cx + rad * 0.95), int(cy + rad * 0.55)),
        }

        # edges
        for host in ('h1', 'h2', 'h3'):
            x1, y1 = self.node_pos['s1']
            x2, y2 = self.node_pos[host]
            self.canvas.create_line(
                x1, y1, x2, y2,
                fill=C['border'], width=2, dash=(6, 4),
                tags=f'edge_{host}',
            )

        # nodes
        r = 24
        cfg = {
            's1': (C['accent'], 's1\nSwitch'),
            'h1': (C['green'],  'h1\n10.0.0.1'),
            'h2': (C['green'],  'h2\n10.0.0.2'),
            'h3': (C['green'],  'h3\n10.0.0.3'),
        }
        self.node_oval  = {}
        self.node_color = {}

        for node, (color, label) in cfg.items():
            x, y = self.node_pos[node]
            # soft glow ring
            self.canvas.create_oval(
                x-r-8, y-r-8, x+r+8, y+r+8,
                fill='', outline=color, width=1,
                tags=f'glow_{node}',
            )
            # main body
            oval = self.canvas.create_oval(
                x-r, y-r, x+r, y+r,
                fill=C['card'], outline=color, width=2,
                tags=f'node_{node}',
            )
            self.node_oval[node]  = oval
            self.node_color[node] = color
            # label
            self.canvas.create_text(
                x, y, text=label,
                fill=color, font=('Courier New', 7, 'bold'),
                justify='center',
            )

        # mark blocked hosts immediately after redraw
        if self.network:
            for ip in self.network.controller.blocked_ips:
                host = self._IP_HOST.get(ip)
                if host:
                    self._set_node_color(host, C['red'])

    # --------------------------------------------------
    def _set_node_color(self, node, color):
        if node not in self.node_oval:
            return
        self.canvas.itemconfig(self.node_oval[node],
                               outline=color, fill=C['card'])
        self.canvas.itemconfig(f'glow_{node}', outline=color)
        self.node_color[node] = color

    # --------------------------------------------------
    def _flash_node(self, node, color, cycles=5, ms=120):
        if node not in self.node_oval:
            return
        orig = self.node_color.get(node, C['green'])
        oval = self.node_oval[node]

        def toggle(n=0):
            if n >= cycles * 2:
                # leave red if now blocked
                if self.network and any(
                    self._IP_HOST.get(ip) == node
                    for ip in self.network.controller.blocked_ips
                ):
                    self.canvas.itemconfig(oval, outline=C['red'], fill=C['card'])
                    self.canvas.itemconfig(f'glow_{node}', outline=C['red'])
                else:
                    self.canvas.itemconfig(oval, outline=orig, fill=C['card'])
                    self.canvas.itemconfig(f'glow_{node}', outline=orig)
                return
            col = color if n % 2 == 0 else orig
            bg  = '#2a0010' if (n % 2 == 0 and color == C['red']) else C['card']
            self.canvas.itemconfig(oval, outline=col, fill=bg)
            self.canvas.itemconfig(f'glow_{node}', outline=col)
            self.root.after(ms, toggle, n + 1)

        toggle()

    # --------------------------------------------------
    def _animate_packet(self, src_node, dst_node, color):
        """Animate a glowing dot: src → switch → dst."""
        if src_node not in self.node_pos or dst_node not in self.node_pos:
            return

        sx, sy = self.node_pos[src_node]
        mx, my = self.node_pos['s1']
        ex, ey = self.node_pos[dst_node]

        steps = 18
        path  = []
        for i in range(steps + 1):
            t = i / steps
            path.append((sx + (mx - sx)*t, sy + (my - sy)*t))
        for i in range(1, steps + 1):
            t = i / steps
            path.append((mx + (ex - mx)*t, my + (ey - my)*t))

        dot = self.canvas.create_oval(-12, -12, -4, -4,
                                      fill=color, outline='white',
                                      width=1, tags='pkt')

        def move(i=0):
            if i >= len(path):
                self.canvas.delete(dot)
                return
            x, y = path[i]
            self.canvas.coords(dot, x-5, y-5, x+5, y+5)
            self.root.after(25, move, i + 1)

        move()

    # ==================================================
    # STDOUT HANDLER
    # ==================================================
    def _on_print(self, text):
        """Called from any thread — schedule GUI update safely."""
        self.root.after(0, self._handle_output, text)

    # --------------------------------------------------
    def _handle_output(self, text):
        lines = text.split('\n')
        for line in lines:
            if not line.strip():
                continue
            self._log_line(line)

    # --------------------------------------------------
    def _log_line(self, line):
        tag = 'default'
        anim_src = anim_dst = None
        flash = flash_color = None

        if '📦 Packet Forwarded:' in line:
            tag = 'normal'
            try:
                rest = line.split('Packet Forwarded:')[1].strip()
                parts = rest.split('→')
                anim_src = self._IP_HOST.get(parts[0].strip())
                anim_dst = self._IP_HOST.get(parts[1].strip())
            except Exception:
                pass

        elif 'ALERT: IP SPOOFING' in line or 'SPOOFING' in line:
            tag = 'spoof'
            self._flash_all_nodes(C['orange'])

        elif 'ALERT: DOS ATTACK' in line or 'DOS' in line and 'ALERT' in line:
            tag = 'alert'

        elif '🚫 BLOCKED TRAFFIC FROM' in line:
            tag = 'blocked'
            try:
                ip = line.split('FROM')[1].strip()
                flash = self._IP_HOST.get(ip)
                flash_color = C['red']
            except Exception:
                pass

        elif '🚨' in line or 'ALERT' in line:
            tag = 'alert'

        elif 'Attacker' in line and ':' in line:
            tag = 'alert'
            try:
                ip = line.split(':')[1].strip()
                flash = self._IP_HOST.get(ip)
                flash_color = C['red']
            except Exception:
                pass

        elif '🔥' in line or 'FLOOD ATTACK' in line:
            tag = 'alert'

        elif any(k in line for k in ('SDN Controller', 'Monitoring', 'TOPOLOGY',
                                      'STATISTICS', 'Ping Completed', 'STEP')):
            tag = 'info'

        elif '❌' in line:
            tag = 'alert'

        elif '====' in line or '----' in line or line.strip().startswith('|'):
            tag = 'muted'

        # write to log
        ts = time.strftime('%H:%M:%S')
        self.log.config(state='normal')
        self.log.insert('end', f"[{ts}] ", 'ts')
        self.log.insert('end', line + '\n', tag)
        self.log.see('end')
        self.log.config(state='disabled')

        # topology effects
        if anim_src and anim_dst:
            col = {'normal': C['green'], 'alert': C['red'],
                   'spoof':  C['orange'], 'blocked': C['yellow']}.get(tag, C['green'])
            self._animate_packet(anim_src, anim_dst, col)

        if flash and flash_color:
            self._flash_node(flash, flash_color)

        # status bar
        if tag == 'alert':
            self._v_status.set(f"⚠  SECURITY ALERT — {ts}")
        elif tag == 'spoof':
            self._v_status.set(f"⚠  IP SPOOFING DETECTED — {ts}")
        elif tag == 'blocked':
            self._v_status.set(f"🚫  Host Blocked — {ts}")
        elif tag == 'normal':
            self._v_status.set(f"✓  Packet forwarded — {ts}")

    # --------------------------------------------------
    def _flash_all_nodes(self, color):
        for node in ('h1', 'h2', 'h3', 's1'):
            self._flash_node(node, color, cycles=3, ms=180)

    # ==================================================
    # COMMAND RUNNER
    # ==================================================
    def _run(self, command):
        if self._busy:
            self._v_status.set("⏳  Operation in progress — please wait …")
            return
        self._busy = True
        self._v_status.set(f"Running: {command} …")

        def task():
            try:
                self.network.execute_command(command)
            finally:
                self.root.after(0, self._done)

        threading.Thread(target=task, daemon=True).start()

    def _done(self):
        self._busy = False
        self._v_status.set("Ready — select an action from the left panel")

    # ==================================================
    # HELPERS
    # ==================================================
    def _clear_log(self):
        self.log.config(state='normal')
        self.log.delete('1.0', 'end')
        self.log.config(state='disabled')

    def _tick_stats(self):
        """Refresh header counters every 400 ms."""
        if self.network:
            c = self.network.controller
            self._v_packets.set(c.total_packets)
            self._v_alerts.set(c.total_alerts)
            self._v_blocked.set(len(c.blocked_ips))
        self.root.after(400, self._tick_stats)


# =========================================================
# ENTRY POINT
# =========================================================
if __name__ == "__main__":
    root = tk.Tk()
    app  = SDNSimulatorGUI(root)
    root.mainloop()
