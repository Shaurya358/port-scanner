GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"
import socket
import time

print(CYAN + "=" * 50 + RESET)
print(CYAN + "        BASIC TCP PORT SCANNER v1.0" + RESET)
print(CYAN + "=" * 50 + RESET)


target = input("Enter Target IP: ")
start_port = int(input("Enter Start Port: "))
end_port = int(input("Enter End Port: "))

print("\nScanning target:", target)
print("Port range:", start_port, "to", end_port)
print("-" * 50)

start_time = time.time()

open_ports = []

for port in range(start_port, end_port + 1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target, port))

        if result == 0:
            print(f"{GREEN}[OPEN]{RESET} Port {port}")


        s.close()

    except KeyboardInterrupt:
        print("\nScan stopped by user.")
        break

    except socket.gaierror:
        print("Hostname could not be resolved.")
        break

    except socket.error:
        print("Couldn't connect to server.")
        break

end_time = time.time()

print(YELLOW + "\nScan Completed." + RESET)
print(f"{CYAN}Total Open Ports:{RESET} {len(open_ports)}")
print(f"{CYAN}Time Taken:{RESET} {round(end_time - start_time, 2)} seconds")

