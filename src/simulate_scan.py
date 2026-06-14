"""
Safe Local Port Scan Simulator
================================
Rapidly opens TCP connections to a range of ports on the target IP
to trigger the SOAR engine's Stealth Recon detection vector.
This is a safe, controlled simulation -- no exploits, no payloads.
"""

import socket
import sys
import time
import io

# Fix Windows console encoding for emoji support
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


def simulate_port_scan(target: str = "127.0.0.1",
                       port_start: int = 8000,
                       port_end: int = 8050,
                       timeout: float = 0.02):
    """Sweep *target* across ports [port_start, port_end) via TCP SYN."""
    total = port_end - port_start
    open_ports = []

    print(f"[SCAN] Initiating Safe Port Scan Simulation -> {target}")
    print(f"       Range: {port_start}-{port_end}  |  Timeout: {timeout}s\n")

    start = time.time()
    for port in range(port_start, port_end):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except OSError:
            pass

    elapsed = time.time() - start
    print(f"[DONE] Reconnaissance sweep complete.")
    print(f"       Ports probed : {total}")
    print(f"       Open ports   : {open_ports if open_ports else 'None'}")
    print(f"       Duration     : {elapsed:.2f}s")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    simulate_port_scan(target)