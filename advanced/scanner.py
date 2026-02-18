import argparse
import json
import random
import signal
import sys
import socket
import threading
from queue import Queue
from datetime import datetime
from scapy.all import *

conf.verb = 0

# ================= COLORS =================
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

# ================= ASCII BANNER =================
print(C.RED + C.BOLD + r"""
    ___       __                          __                 
   /   | ____/ /   _____  _________  ____/ /___  __________ 
  / /| |/ __  / | / / _ \/ ___/ __ \/ __  / __ \/ ___/ ___/ 
 / ___ / /_/ /| |/ /  __/ /  / /_/ / /_/ / /_/ / /  (__  )  
/_/  |_\__,_/ |___/\___/_/   \____/\__,_/\____/_/  /____/   

            A D V A N C E D   P O R T   S C A N N E R
""" + C.RESET)

# ================= CTRL+C =================
def signal_handler(sig, frame):
    print(f"\n{C.RED}Scan Interrupted by User.{C.RESET}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ================= ARGUMENTS =================
parser = argparse.ArgumentParser(description="Advanced ASCII Port Scanner")

parser.add_argument("-t", "--target", required=True, help="Target IP")
parser.add_argument("-p", "--ports", default="1-1024", help="Port range")
parser.add_argument("-s", "--scan", required=True,
                    choices=["syn", "fin", "null", "xmas", "ack"],
                    help="Scan type")
parser.add_argument("--top", action="store_true", help="Scan Top 1000 Ports")
parser.add_argument("--threads", type=int, default=80, help="Thread count")

args = parser.parse_args()

target = args.target
scan_type = args.scan
threads_count = args.threads

if args.top:
    ports = list(range(1, 1001))
else:
    start, end = map(int, args.ports.split("-"))
    ports = list(range(start, end + 1))

random.shuffle(ports)

# ================= STATUS =================
print(C.CYAN + f"Target      : {target}" + C.RESET)
print(C.CYAN + f"Scan Type   : {scan_type.upper()}" + C.RESET)
print(C.CYAN + f"Total Ports : {len(ports)}" + C.RESET)
print(C.CYAN + f"Threads     : {threads_count}" + C.RESET)
print()

# ================= HOST DISCOVERY =================
arp = ARP(pdst=target)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether / arp
result = srp(packet, timeout=2)[0]

if result:
    print(C.GREEN + "[+] Host is UP" + C.RESET)
else:
    print(C.YELLOW + "[!] No ARP reply (continuing scan)" + C.RESET)

print()

# ================= SCAN ENGINE =================
open_ports = []
lock = threading.Lock()
queue = Queue()

for p in ports:
    queue.put(p)

def syn_scan(port):
    pkt = IP(dst=target)/TCP(dport=port, flags="S")
    res = sr1(pkt, timeout=1)
    if res and res.haslayer(TCP):
        if res[TCP].flags & 0x12:
            with lock:
                open_ports.append(port)
            send(IP(dst=target)/TCP(dport=port, flags="R"))

def fin_scan(port):
    pkt = IP(dst=target)/TCP(dport=port, flags="F")
    if not sr1(pkt, timeout=1):
        with lock:
            open_ports.append(port)

def null_scan(port):
    pkt = IP(dst=target)/TCP(dport=port, flags="")
    if not sr1(pkt, timeout=1):
        with lock:
            open_ports.append(port)

def xmas_scan(port):
    pkt = IP(dst=target)/TCP(dport=port, flags="FPU")
    if not sr1(pkt, timeout=1):
        with lock:
            open_ports.append(port)

def ack_scan(port):
    pkt = IP(dst=target)/TCP(dport=port, flags="A")
    sr1(pkt, timeout=1)

def worker():
    while not queue.empty():
        port = queue.get()

        if scan_type == "syn":
            syn_scan(port)
        elif scan_type == "fin":
            fin_scan(port)
        elif scan_type == "null":
            null_scan(port)
        elif scan_type == "xmas":
            xmas_scan(port)
        elif scan_type == "ack":
            ack_scan(port)

        queue.task_done()

# ================= START SCAN =================
start_time = datetime.now()

threads = []

for _ in range(threads_count):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

queue.join()

end_time = datetime.now()

# ================= RESULTS =================
print()
print(C.BOLD + "Open Ports:" + C.RESET)

if not open_ports:
    print(C.RED + "No open ports found." + C.RESET)
else:
    for port in sorted(open_ports):
        print(C.GREEN + f"  -> Port {port} OPEN" + C.RESET)

# ================= SUMMARY =================
duration = (end_time - start_time).total_seconds()

print()
print(C.BOLD + "Scan Summary:" + C.RESET)
print(C.BLUE + f"Total Open Ports : {len(open_ports)}" + C.RESET)
print(C.BLUE + f"Scan Duration    : {duration} seconds" + C.RESET)

# ================= SAVE REPORT =================
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
filename = f"advanced_scan_{timestamp}.json"

with open(filename, "w") as f:
    json.dump({
        "target": target,
        "scan_type": scan_type,
        "open_ports": open_ports,
        "duration": duration
    }, f, indent=4)

print()
print(C.GREEN + f"Report saved : {filename}" + C.RESET)
print()
