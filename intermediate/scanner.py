import socket
import threading
import time
import argparse
from queue import Queue

# -------- Color Codes --------
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

# -------- Argument Parser --------
parser = argparse.ArgumentParser(description="Intermediate Port Scanner v2.0")
parser.add_argument("-t", "--target", required=True, help="Target IP")
parser.add_argument("-p", "--ports", required=True, help="Port range (e.g., 20-80)")
parser.add_argument("-s", "--scan", required=True, choices=["tcp", "udp"], help="Scan type")

args = parser.parse_args()

target = args.target
scan_type = args.scan
start_port, end_port = map(int, args.ports.split("-"))

# -------- Header --------
print(CYAN + "=" * 60 + RESET)
print(CYAN + "        INTERMEDIATE PORT SCANNER v2.0" + RESET)
print(CYAN + "=" * 60 + RESET)

print(f"{BLUE}[INFO]{RESET} Target     : {target}")
print(f"{BLUE}[INFO]{RESET} Port Range : {start_port}-{end_port}")
print(f"{BLUE}[INFO]{RESET} Scan Type  : {scan_type.upper()}")
print("-" * 60)

queue = Queue()
open_ports = []
lock = threading.Lock()

# -------- Banner Grab --------
def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner
    except:
        return None

# -------- TCP Scan --------
def tcp_scan(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target, port))

        if result == 0:
            with lock:
                print(f"{GREEN}[OPEN]{RESET} Port {port}")
                open_ports.append(port)

                banner = banner_grab(target, port)
                if banner:
                    print(f"   {YELLOW}↳ Service:{RESET} {banner}")

        s.close()
    except:
        pass

# -------- UDP Scan --------
def udp_scan(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b"", (target, port))
        try:
            data, _ = s.recvfrom(1024)
            with lock:
                print(f"{GREEN}[OPEN]{RESET} UDP Port {port}")
                open_ports.append(port)
        except socket.timeout:
            pass
        s.close()
    except:
        pass

# -------- Worker --------
def worker():
    while not queue.empty():
        port = queue.get()

        if scan_type == "tcp":
            tcp_scan(port)
        elif scan_type == "udp":
            udp_scan(port)

        queue.task_done()

# -------- Fill Queue --------
for port in range(start_port, end_port + 1):
    queue.put(port)

# -------- Start Scan --------
start_time = time.time()

threads = []

for _ in range(50):  # 50 threads
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

queue.join()

end_time = time.time()

# -------- Summary --------
print("\n" + CYAN + "=" * 60 + RESET)
print(CYAN + "SCAN SUMMARY" + RESET)
print(CYAN + "=" * 60 + RESET)

print(f"{BLUE}Total Open Ports:{RESET} {len(open_ports)}")
print(f"{BLUE}Open Ports      :{RESET} {sorted(open_ports)}")
print(f"{BLUE}Time Taken      :{RESET} {round(end_time - start_time, 2)} seconds")
print("-" * 60)

# -------- Save Results --------
with open("scan_results.txt", "w") as f:
    for port in open_ports:
        f.write(f"Port {port} is open\n")

print(f"{GREEN}[✓]{RESET} Results saved to scan_results.txt")
