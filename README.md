"""
AstraSOAR — Autonomous Streaming Threat Response & Analysis
===========================================================

This is the core backend engine of AstraSOAR. It acts as a physical-layer 
Intrusion Detection and Prevention System (IDPS). 

It binds directly to the Network Interface Card (NIC) via Scapy to sniff raw 
packets in real time. It utilizes a decoupled, three-stage agent pipeline:
  1. Ingress Sensor (Data Plane): Detects volumetric floods and port scans.
  2. Intelligence Agent (Reasoning Plane): Calculates Shannon Entropy and queries Gemini AI.
  3. Remediator Agent (Action Plane): Compiles firewall rules and exports forensic PDFs.
"""

import os
import sys
import io
import json
import math
import time
import signal
import logging
import threading
from datetime import datetime
from collections import defaultdict

# ---------------------------------------------------------------------------
# Console Encoding Fix
# ---------------------------------------------------------------------------
# Windows command prompts often crash when trying to print Unicode emojis.
# This forces the standard output/error streams to handle emojis safely.
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from scapy.all import IP, TCP, UDP, conf, sniff

# ---------------------------------------------------------------------------
# Optional: Gemini AI Analyst Integration
# ---------------------------------------------------------------------------
# We wrap this in a try-except block so the engine doesn't crash if the 
# generative AI library isn't installed. It will gracefully degrade to rule-based logic.
try:
    import google.generativeai as genai
    _HAS_GENAI = True
except ImportError:
    _HAS_GENAI = False

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("SOAR")


# ---------------------------------------------------------------------------
# Cross-Platform File Locking Helpers
# ---------------------------------------------------------------------------
# Because app.py writes to live_soar_logs.json and gui.py reads from it 
# simultaneously, we need OS-level file locking to prevent file corruption.
def _lock_file(f):
    """Acquire an exclusive lock on the file to prevent race conditions."""
    if sys.platform == "win32":
        import msvcrt
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
    else:
        import fcntl
        fcntl.flock(f, fcntl.LOCK_EX)


def _unlock_file(f):
    """Release the exclusive lock on the file."""
    if sys.platform == "win32":
        import msvcrt
        try:
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    else:
        import fcntl
        fcntl.flock(f, fcntl.LOCK_UN)


# ---------------------------------------------------------------------------
# Payload Mathematical Analysis
# ---------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    """
    Calculates the Shannon Entropy of the raw packet bytes.
    Returns a float between 0.0 and 8.0.
    
    Why this matters: Normal text/data has low entropy. Encrypted, obfuscated, 
    or heavily packed malware payloads have high entropy (approaching 8.0). 
    This allows the SOAR to mathematically detect suspicious payloads.
    """
    if not data:
        return 0.0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


# ---------------------------------------------------------------------------
# Core SOAR Engine
# ---------------------------------------------------------------------------
class RealTimeActiveSOAR:
    """Live network intrusion detection, classification & response engine."""

    # --- Tunable Detection Thresholds ---
    # These dictate how sensitive the intrusion detection system is.
    FLOOD_BYTE_THRESHOLD = 500        # Minimum packet size to be considered part of a volumetric attack
    FLOOD_PPS_THRESHOLD = 40          # Packets-per-second required to trigger a Flood Alert
    RECON_PORT_THRESHOLD = 15         # Unique ports scanned by a single IP to trigger a Recon Alert
    MATRIX_RESET_INTERVAL = 1.0       # The rolling time window (in seconds) for traffic aggregation
    MAX_LOG_ENTRIES = 50              # Keep the JSON log lightweight by only storing the 50 newest alerts
    COOLDOWN_SECONDS = 5              # Prevents alert fatigue by silencing duplicate alerts from the same IP

    def __init__(self):
        # Resolve absolute paths relative to the project root directory
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.log_file = os.path.join(self.project_root, "data", "live_soar_logs.json")
        self.report_dir = os.path.join(self.project_root, "data", "reports")
        os.makedirs(self.report_dir, exist_ok=True)

        # Matrices used to aggregate packet data in real-time
        self._ip_velocity: dict[str, int] = {}
        self._port_scan: dict[str, set] = {}
        self._last_reset = time.time()

        # Threading lock and deduplication tracking
        self._alert_cooldown: dict[tuple, float] = {}
        self._lock = threading.Lock()

        # Performance telemetry
        self.stats = {"packets_processed": 0, "threats_detected": 0}

        # Initialize the Gemini LLM
        self._init_ai()

        # Wipe the old log file clean on startup
        self._write_log_file([])
        log.info("🛸 SOAR Core Online — engine armed.")

    def _init_ai(self):
        """Authenticates and initializes the Gemini Generative AI model."""
        self.llm = None
        api_key = os.environ.get("GEMINI_API_KEY")
        if api_key and _HAS_GENAI:
            try:
                genai.configure(api_key=api_key)
                self.llm = genai.GenerativeModel("gemini-2.5-flash")
                log.info("🧠 Gemini AI Analyst linked.")
            except Exception as exc:
                log.warning("AI init failed: %s — falling back to rule engine.", exc)

    # -----------------------------------------------------------------------
    # PDF Forensic Report Generator
    # -----------------------------------------------------------------------
    def export_incident_report(self, log_entry: dict) -> str:
        """
        Dynamically generates a highly structured PDF forensic report for compliance.
        Uses universal line-break syntax (ln=1) to ensure compatibility across all FPDF versions.
        """
        from fpdf import FPDF

        # Generate a unique timestamped filename
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"incident_{ts}.pdf"
        filepath = os.path.join(self.report_dir, filename)

        # Standard A4 usable width with 15mm margins = 180mm
        LEFT_MARGIN = 15
        COL_FIELD = 55
        COL_VALUE = 125
        ROW_H = 9

        try:
            pdf = FPDF()
            pdf.set_margins(LEFT_MARGIN, 10, LEFT_MARGIN)
            pdf.set_auto_page_break(auto=True, margin=25)
            pdf.add_page()

            # ── Header Banner ──
            pdf.set_fill_color(15, 23, 42)
            pdf.rect(0, 0, 210, 48, "F")
            pdf.set_text_color(56, 189, 248)
            pdf.set_font("Helvetica", "B", 24)
            pdf.set_y(10)
            pdf.cell(0, 14, "AstraSOAR", align="C", ln=1)
            pdf.set_font("Helvetica", "", 11)
            pdf.set_text_color(148, 163, 184)
            pdf.cell(0, 8, "FORENSIC INCIDENT REPORT", align="C", ln=1)
            
            # Thin accent line under header
            pdf.set_draw_color(56, 189, 248)
            pdf.set_line_width(0.6)
            pdf.line(60, 38, 150, 38)
            pdf.ln(18)

            # ── Dynamic Severity Badge ──
            entropy = log_entry.get("entropy", 0)
            if entropy >= 8.0:
                severity, sev_r, sev_g, sev_b = "CRITICAL", 239, 68, 68
            elif entropy >= 5.0:
                severity, sev_r, sev_g, sev_b = "HIGH", 249, 115, 22
            else:
                severity, sev_r, sev_g, sev_b = "MEDIUM", 234, 179, 8

            pdf.set_fill_color(sev_r, sev_g, sev_b)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(65, 11, f"  SEVERITY: {severity}", fill=True, ln=1)
            pdf.ln(8)

            # ── Data Parsing ──
            # Separate short fields (IPs, sizes) from long fields (AI text, commands) for table rendering
            short_fields = {}
            long_fields = {}
            for k, v in log_entry.items():
                if k == "agent_pipeline":       # Skip nested pipeline JSON
                    continue
                val_str = str(v)
                if len(val_str) > 60 or k in ("ai_summary", "command"):
                    long_fields[k] = val_str
                else:
                    short_fields[k] = val_str

            # ── Short-field Table Render ──
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_fill_color(30, 41, 59)
            pdf.set_text_color(226, 232, 240)
            pdf.set_x(LEFT_MARGIN)
            pdf.cell(COL_FIELD, ROW_H, "  FIELD", border=1, fill=True, ln=0)
            pdf.cell(COL_VALUE, ROW_H, "  VALUE", border=1, fill=True, ln=1)

            row_alt = False
            for key, value in short_fields.items():
                fill_color = (241, 245, 249) if row_alt else (255, 255, 255)
                pdf.set_fill_color(*fill_color)
                label = key.upper().replace("_", " ")

                display_value = value if len(value) <= 60 else value[:57] + "..."

                pdf.set_x(LEFT_MARGIN)
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(30, 41, 59)
                pdf.cell(COL_FIELD, ROW_H, f"  {label}", border=1, fill=True, ln=0)

                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(51, 65, 85)
                pdf.cell(COL_VALUE, ROW_H, f"  {display_value}", border=1, fill=True, ln=1)

                row_alt = not row_alt
            pdf.ln(8)

            # ── Long-text Sections Render ──
            for key, value in long_fields.items():
                label = key.upper().replace("_", " ")
                total_width = COL_FIELD + COL_VALUE

                pdf.set_x(LEFT_MARGIN)
                pdf.set_fill_color(30, 41, 59)
                pdf.set_text_color(226, 232, 240)
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(total_width, ROW_H, f"  {label}", border=1, fill=True, ln=1)

                pdf.set_x(LEFT_MARGIN)
                pdf.set_fill_color(248, 250, 252)
                pdf.set_text_color(30, 41, 59)
                pdf.set_font("Helvetica", "", 9)
                pdf.multi_cell(total_width, 7, f"  {value}", border=1, fill=True)
                pdf.ln(4)

            # ── Footer ──
            pdf.ln(6)
            pdf.set_draw_color(148, 163, 184)
            pdf.set_line_width(0.3)
            pdf.line(15, pdf.get_y(), 195, pdf.get_y())
            pdf.ln(4)
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(148, 163, 184)
            gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
            pdf.cell(0, 5,
                     f"Report generated: {gen_time}  |  "
                     f"AstraSOAR Autonomous Defense Platform",
                     align="C", ln=1)

            pdf.output(filepath)

        except Exception as exc:
            log.error("Failed to write PDF report %s: %s", filename, exc)

        return filename

    # -----------------------------------------------------------------------
    # AI Threat Brief Generation
    # -----------------------------------------------------------------------
    def generate_analyst_report(self, attack_type: str, src_ip: str,
                                raw_bytes: int, entropy: float) -> str:
        """Asks the Gemini AI to generate a human-readable threat brief."""
        if self.llm:
            try:
                # Prompt engineering to force a concise, professional SOC summary
                prompt = (
                    f"You are a Lead SOC Analyst. Provide a concise 2-sentence "
                    f"incident brief for: Attack={attack_type}, Source IP={src_ip}, "
                    f"Payload={raw_bytes} bytes, Shannon Entropy={entropy:.2f}/8.0."
                )
                response = self.llm.generate_content(prompt)
                return response.text.strip()
            except Exception as exc:
                log.warning("AI generation failed: %s", exc)

        # Deterministic fallback if API fails or key is missing
        severity = "CRITICAL" if entropy > 6.0 else "HIGH"
        return (
            f"[{severity}] {attack_type} detected from {src_ip} "
            f"({raw_bytes}B payload, entropy {entropy:.2f}). "
            f"Automated defense protocols engaged."
        )

    # -----------------------------------------------------------------------
    # Physical Packet Sniffing (The Hot Path)
    # -----------------------------------------------------------------------
    def packet_callback(self, packet):
        """
        Executed on every single packet captured by the NIC. 
        Must be highly optimized to prevent dropping packets.
        """
        if not packet.haslayer(IP):
            return

        self.stats["packets_processed"] += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        raw_bytes = len(packet)
        now = time.time()

        # Reset aggregation matrices if the time window has passed
        if now - self._last_reset > self.MATRIX_RESET_INTERVAL:
            self._ip_velocity.clear()
            self._port_scan.clear()
            self._last_reset = now

        # --- Detection Vector 1: Volumetric TCP Flood ---
        if raw_bytes > self.FLOOD_BYTE_THRESHOLD:
            self._ip_velocity[src_ip] = self._ip_velocity.get(src_ip, 0) + 1
            if self._ip_velocity[src_ip] > self.FLOOD_PPS_THRESHOLD:
                entropy = shannon_entropy(bytes(packet))
                self._maybe_alert("VOLUMETRIC_FLOOD", src_ip, dst_ip,
                                  raw_bytes, entropy)
                self._ip_velocity[src_ip] = 0  # reset to avoid alert spam

        # --- Detection Vector 2: Stealth Port Reconnaissance ---
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            self._port_scan.setdefault(src_ip, set()).add(dst_port)
            if len(self._port_scan[src_ip]) > self.RECON_PORT_THRESHOLD:
                entropy = shannon_entropy(bytes(packet))
                self._maybe_alert("STEALTH_RECON", src_ip, dst_ip,
                                  raw_bytes, entropy)
                self._port_scan[src_ip].clear()

        # --- Detection Vector 3: Volumetric UDP Flood ---
        if packet.haslayer(UDP) and raw_bytes > self.FLOOD_BYTE_THRESHOLD:
            self._ip_velocity[src_ip] = self._ip_velocity.get(src_ip, 0) + 1
            if self._ip_velocity[src_ip] > self.FLOOD_PPS_THRESHOLD:
                entropy = shannon_entropy(bytes(packet))
                self._maybe_alert("UDP_FLOOD", src_ip, dst_ip,
                                  raw_bytes, entropy)
                self._ip_velocity[src_ip] = 0

    def _maybe_alert(self, attack_type, src_ip, dst_ip, raw_bytes, entropy):
        """Rate-limits identical alerts to prevent JSON log bloat."""
        key = (attack_type, src_ip)
        now = time.time()
        with self._lock:
            last = self._alert_cooldown.get(key, 0)
            if now - last < self.COOLDOWN_SECONDS:
                return
            self._alert_cooldown[key] = now
        self._log_threat(attack_type, src_ip, dst_ip, raw_bytes, entropy)

    # -----------------------------------------------------------------------
    # Logging and Pipeline Construction
    # -----------------------------------------------------------------------
    def _log_threat(self, attack_type, src_ip, dst_ip, raw_bytes, entropy):
        """Constructs the JSON log entry containing the full Agent Pipeline trace."""
        self.stats["threats_detected"] += 1

        # Normalize raw entropy (0-8 scale) to a 0-10 scale for easier UI visualization
        entropy_normalised = round(min(entropy / 8.0 * 10.0, 10.0), 1)

        # ── Step-by-Step Agent Pipeline Trace ──
        pipeline = []

        # 1. Ingress Sensor (Data Plane) Execution
        t1 = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if attack_type == "VOLUMETRIC_FLOOD":
            sensor_detail = (
                f"Packet velocity from {src_ip} exceeded {self.FLOOD_PPS_THRESHOLD} pps "
                f"threshold. Payload size: {raw_bytes}B (>{self.FLOOD_BYTE_THRESHOLD}B limit)."
            )
        elif attack_type == "STEALTH_RECON":
            sensor_detail = (
                f"Port sweep from {src_ip} exceeded {self.RECON_PORT_THRESHOLD} unique "
                f"destination ports within {self.MATRIX_RESET_INTERVAL}s window."
            )
        elif attack_type == "UDP_FLOOD":
            sensor_detail = (
                f"UDP flood from {src_ip} exceeded {self.FLOOD_PPS_THRESHOLD} pps "
                f"with {raw_bytes}B payloads."
            )
        else:
            sensor_detail = f"Anomalous traffic pattern detected from {src_ip}."

        pipeline.append({
            "agent": "INGRESS SENSOR", "role": "Data Plane", "icon": "radar",
            "time": t1, "status": "complete",
            "action": f"Anomaly flagged: {attack_type.replace('_', ' ')}",
            "detail": sensor_detail,
        })

        # 2. Intelligence Agent (Reasoning Plane) Execution
        t2 = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        ai_summary = self.generate_analyst_report(attack_type, src_ip, raw_bytes, entropy)
        t2_end = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        pipeline.append({
            "agent": "INTELLIGENCE AGENT", "role": "Reasoning Plane", "icon": "brain",
            "time": t2, "status": "complete",
            "action": f"Shannon entropy computed: {entropy:.3f}/8.0 (normalised: {entropy_normalised}/10)",
            "detail": f"AI Analyst generated executive brief. Processing: {t2} → {t2_end}.",
        })

        # 3. Remediator Agent (Action Plane) Execution
        t3 = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Compile the autonomous firewall defense string
        fw_command = f"iptables -A INPUT -s {src_ip} -j REJECT --reject-with tcp-reset"

        log_entry = {
            "timestamp": t1.split(".")[0],
            "attack_type": attack_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "bytes": raw_bytes,
            "entropy": entropy_normalised,
            "shannon_raw": round(entropy, 3),
            "command": fw_command,
            "ai_summary": ai_summary,
        }

        # Generate the PDF and attach the filename to the log for dashboard download
        report_name = self.export_incident_report(log_entry)
        log_entry["report_file"] = report_name

        pipeline.append({
            "agent": "REMEDIATOR AGENT", "role": "Action Plane", "icon": "shield",
            "time": t3, "status": "complete",
            "action": "Firewall rule compiled & forensic report exported",
            "detail": f"Generated {report_name}. Defense command staged: {fw_command}",
        })

        log_entry["agent_pipeline"] = pipeline

        # Thread-safe write to the JSON file
        self._append_log(log_entry)

        # Print visual warning to the backend terminal
        log.warning(
            "🚨 %s  src=%s  dst=%s  %dB  entropy=%.1f/10",
            attack_type, src_ip, dst_ip, raw_bytes, entropy_normalised,
        )

    # -----------------------------------------------------------------------
    # JSON File IO
    # -----------------------------------------------------------------------
    def _append_log(self, entry: dict):
        """Acquires lock and safely appends the new threat to the JSON file."""
        with self._lock:
            try:
                data = self._read_log_file()
                data.append(entry)
                # Enforce the rolling window (drop old logs)
                self._write_log_file(data[-self.MAX_LOG_ENTRIES:])
            except Exception as exc:
                log.error("Log write failed: %s", exc)

    def _read_log_file(self) -> list:
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                return json.loads(content) if content else []
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _write_log_file(self, data: list):
        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    # -----------------------------------------------------------------------
    # Main Sniff Loop
    # -----------------------------------------------------------------------
    def run(self, iface=None):
        """Starts the blocking packet capture loop."""
        iface = iface or conf.iface
        log.info("🔒 GUARD MODE — sniffing on %s ...", iface)
        try:
            # store=0 is critical to prevent a memory leak (forces Scapy to discard packets after callback)
            sniff(iface=iface, prn=self.packet_callback, store=0)
        except KeyboardInterrupt:
            log.info("⛔ Operator shutdown — engine halted.")
        except PermissionError:
            # Raw socket sniffing requires kernel-level privileges
            log.critical(
                "❌ Insufficient privileges. Run as Administrator / root."
            )
            sys.exit(1)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    soar = RealTimeActiveSOAR()

    # Graceful shutdown handler to print final statistics when Ctrl+C is pressed
    def _handle_sigint(sig, frame):
        log.info(
            "📊 Session stats — packets: %d, threats: %d",
            soar.stats["packets_processed"],
            soar.stats["threats_detected"],
        )
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_sigint)
    soar.run()
