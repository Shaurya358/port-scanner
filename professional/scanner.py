import socket
import threading
import time
import argparse
from queue import Queue

# -------- Color Codes --------
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

# -------- Argument Parser --------
parser = argparse.ArgumentParser(description="Professional Port Scanner v3.0")

parser.add_argument("-t", "--target", required=True, help="Target IP")
parser.add_argument("-p", "--ports", required=True, help="Port range (e.g., 20-80)")
parser.add_argument("-s", "--scan", required=True, choices=["tcp", "udp"], help="Scan type")
parser.add_argument("-th", "--threads", type=int, default=100, help="Number of threads (default=100)")

args = parser.parse_args()

target = args.target
scan_type = args.scan
threads_count = args.threads
start_port, end_port = map(int, args.ports.split("-"))

# -------- Header --------
print("\n" + Colors.CYAN + "=" * 70 + Colors.RESET)
print(Colors.CYAN + "        PROFESSIONAL PORT SCANNER v3.0" + Colors.RESET)
print(Colors.CYAN + "=" * 70 + Colors.RESET)

print(f"{Colors.BLUE}[INFO]{Colors.RESET} Target     : {target}")
print(f"{Colors.BLUE}[INFO]{Colors.RESET} Port Range : {start_port}-{end_port}")
print(f"{Colors.BLUE}[INFO]{Colors.RESET} Scan Type  : {scan_type.upper()}")
print(f"{Colors.BLUE}[INFO]{Colors.RESET} Threads    : {threads_count}")
print("-" * 70)

queue = Queue()
results = []
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
        return ""

# -------- TCP Scan --------
def tcp_scan(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target, port))

        if result == 0:
            banner = banner_grab(target, port)
            with lock:
                results.append((port, "OPEN", banner))

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
                results.append((port, "OPEN", "UDP Response"))
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

for _ in range(threads_count):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

queue.join()

end_time = time.time()

# -------- Structured Output --------
print("\n" + Colors.CYAN + "-" * 70 + Colors.RESET)
print(f"{'PORT':<10}{'STATUS':<12}{'SERVICE / BANNER'}")
print(Colors.CYAN + "-" * 70 + Colors.RESET)

for port, status, banner in sorted(results):
    print(f"{port:<10}{Colors.GREEN + status + Colors.RESET:<12}{banner}")

print(Colors.CYAN + "-" * 70 + Colors.RESET)

# -------- Summary --------
print("\n" + Colors.CYAN + "=" * 70 + Colors.RESET)
print(Colors.CYAN + "SCAN SUMMARY" + Colors.RESET)
print(Colors.CYAN + "=" * 70 + Colors.RESET)

print(f"{Colors.BLUE}Total Open Ports :{Colors.RESET} {len(results)}")
print(f"{Colors.BLUE}Scan Duration    :{Colors.RESET} {round(end_time - start_time, 2)} seconds")
print(Colors.CYAN + "=" * 70 + Colors.RESET)

# -------- Save Report --------
with open("professional_scan_results.txt", "w") as f:
    for port, status, banner in results:
        f.write(f"{port} {status} {banner}\n")

print(f"{Colors.GREEN}[✓]{Colors.RESET} Results saved to professional_scan_results.txt\n")

