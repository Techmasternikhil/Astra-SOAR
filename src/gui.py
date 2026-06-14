"""
Astra-SOAR — Live Network Dashboard
=====================================
A Streamlit-based real-time SOC (Security Operations Center) console.

Architecture:
  - This file is the FRONTEND only. It does NOT capture packets.
  - The backend engine (app.py) runs separately, sniffs live traffic,
    detects threats, and writes results to `data/live_soar_logs.json`.
  - This dashboard reads that JSON file every 2 seconds and re-renders
    the UI, giving the operator a live view of the defense pipeline.

Usage:
  Terminal 1 (admin):  python src/app.py        ← starts packet capture
  Terminal 2:          streamlit run src/gui.py  ← opens dashboard at localhost:8501
"""

import streamlit as st   # Web UI framework — handles layout, widgets, auto-refresh
import json              # Parses the shared log file written by app.py
import os                # File path resolution, existence checks
import time              # Used for the 2-second auto-refresh sleep
import threading         # Runs network simulations in background threads
import socket            # Creates raw UDP/TCP sockets for attack simulation


# ---------------------------------------------------------------------------
# PAGE CONFIGURATION
# Must be the very first Streamlit call in the script — Streamlit throws an
# error if any other st.* call precedes set_page_config().
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Astra-SOAR Dashboard",   # Browser tab title
    page_icon="🛡️",                      # Browser tab favicon
    layout="wide",                        # Use full browser width (not centered)
    initial_sidebar_state="expanded",     # Show sidebar by default
)


# ---------------------------------------------------------------------------
# PATH RESOLUTION
# __file__ is src/gui.py, so dirname(dirname(...)) gives us the project root.
# This makes paths work regardless of where `streamlit run` is invoked from.
#
# Directory layout expected:
#   project_root/
#   ├── src/
#   │   ├── app.py        ← SOAR engine (backend)
#   │   └── gui.py        ← this file (frontend)
#   └── data/
#       ├── live_soar_logs.json   ← shared log written by app.py
#       └── reports/              ← PDF forensic reports written by app.py
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE     = os.path.join(PROJECT_ROOT, "data", "live_soar_logs.json")
REPORT_DIR   = os.path.join(PROJECT_ROOT, "data", "reports")


# ---------------------------------------------------------------------------
# GLOBAL CSS STYLING
# Injected as raw HTML into the Streamlit page. Uses CSS variables and
# animations to create a dark "cyber SOC" aesthetic.
#
# Key classes defined here:
#   .log-card            — wrapper card for each threat event
#   .severity-*          — left border color by threat severity
#   .badge / .badge-*    — pill badges for attack type labels
#   .metric-card         — the 4 KPI tiles at the top of the dashboard
#   .status-dot          — animated green pulse indicator (GUARD MODE ACTIVE)
#   .pipeline-container  — wrapper for the 3-step agent execution timeline
#   .pipeline-step       — individual step row with connecting vertical line
#   .step-dot            — colored circle with step number (1/2/3)
#   .step-sensor/intel/shield — color variants for each agent type
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    /* ── Overall app background: dark navy gradient ── */
    .stApp {
        background: linear-gradient(135deg, #020617 0%, #0f172a 50%, #020617 100%);
        color: #e2e8f0;
    }

    /* ── Threat event card: glassmorphism panel ── */
    .log-card {
        background: rgba(15, 23, 42, 0.85);
        backdrop-filter: blur(12px);           /* frosted glass blur */
        border: 1px solid rgba(56, 189, 248, 0.15);
        border-radius: 10px;
        padding: 18px 22px;
        margin-bottom: 14px;
        font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
        font-size: 0.88rem;
        transition: transform 0.15s ease, box-shadow 0.15s ease;
    }
    /* Subtle lift effect on hover */
    .log-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px rgba(56, 189, 248, 0.12);
    }

    /* ── Left border color indicates severity level ── */
    .severity-critical { border-left: 5px solid #ef4444; }  /* red   */
    .severity-high     { border-left: 5px solid #f97316; }  /* orange */
    .severity-medium   { border-left: 5px solid #eab308; }  /* yellow */

    /* ── Attack type pill badges ── */
    .badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 999px;     /* fully rounded pill shape */
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.5px;
    }
    .badge-flood  { background: rgba(239, 68, 68, 0.2);  color: #fca5a5; }  /* red tint   */
    .badge-recon  { background: rgba(168, 85, 247, 0.2); color: #c4b5fd; }  /* purple tint */
    .badge-udp    { background: rgba(249, 115, 22, 0.2); color: #fdba74; }  /* orange tint */

    /* ── KPI metric tiles (Total Threats, Flood Events, etc.) ── */
    .metric-card {
        background: rgba(15, 23, 42, 0.7);
        border: 1px solid rgba(56, 189, 248, 0.1);
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    /* Large gradient number */
    .metric-value {
        font-size: 2.4rem;
        font-weight: 700;
        background: linear-gradient(135deg, #38bdf8, #818cf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    /* Small uppercase label beneath the number */
    .metric-label {
        font-size: 0.8rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        margin-top: 6px;
    }

    /* ── Animated green dot (GUARD MODE ACTIVE indicator) ── */
    .status-dot {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 8px;
        animation: pulse-glow 2s infinite;
    }
    .status-active { background: #22c55e; box-shadow: 0 0 8px #22c55e; }
    @keyframes pulse-glow {
        0%, 100% { opacity: 1; }
        50%       { opacity: 0.4; }   /* fades in/out to simulate heartbeat */
    }

    /* Remove the default Streamlit top-bar decoration */
    header[data-testid="stHeader"] { background: transparent; }

    /* ── Agent pipeline timeline container ── */
    .pipeline-container {
        background: rgba(2, 6, 23, 0.6);
        border: 1px solid rgba(56, 189, 248, 0.1);
        border-radius: 8px;
        padding: 16px 20px;
        margin-top: 10px;
    }
    .pipeline-title {
        font-size: 0.78rem;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        margin-bottom: 14px;
        font-weight: 600;
    }

    /* ── Single pipeline step row ── */
    .pipeline-step {
        display: flex;
        align-items: flex-start;
        position: relative;
        padding-left: 36px;   /* space for the dot + connecting line */
        padding-bottom: 18px;
    }
    .pipeline-step:last-child { padding-bottom: 0; }

    /* Vertical connector line drawn between steps using ::before pseudo-element */
    .pipeline-step::before {
        content: '';
        position: absolute;
        left: 13px;
        top: 24px;
        bottom: 0;
        width: 2px;
        background: rgba(56, 189, 248, 0.15);
    }
    /* No connector line after the last step */
    .pipeline-step:last-child::before { display: none; }

    /* ── Numbered circle dot for each step ── */
    .step-dot {
        position: absolute;
        left: 6px;
        top: 4px;
        width: 16px;
        height: 16px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 0.55rem;
        font-weight: 700;
        color: #fff;
    }
    /* Step 1 — blue  (Ingress Sensor Agent) */
    .step-sensor { background: #3b82f6; box-shadow: 0 0 8px rgba(59,130,246,0.4); }
    /* Step 2 — purple (Intelligence Agent) */
    .step-intel  { background: #a855f7; box-shadow: 0 0 8px rgba(168,85,247,0.4); }
    /* Step 3 — green  (Remediator Agent) */
    .step-shield { background: #22c55e; box-shadow: 0 0 8px rgba(34,197,94,0.4); }

    /* ── Text elements inside each pipeline step ── */
    .step-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 3px;
    }
    .step-agent  { font-weight: 700; font-size: 0.82rem; color: #e2e8f0; }
    .step-role   { font-size: 0.7rem; color: #64748b; margin-left: 8px; }
    .step-time   { font-size: 0.7rem; color: #38bdf8; font-family: 'JetBrains Mono', monospace; }
    .step-action { font-size: 0.78rem; color: #cbd5e1; margin-bottom: 2px; }
    .step-detail { font-size: 0.72rem; color: #64748b; line-height: 1.4; }

    /* Small "DONE" badge shown next to each completed agent */
    .step-status {
        display: inline-block;
        padding: 1px 7px;
        border-radius: 999px;
        font-size: 0.62rem;
        font-weight: 600;
        background: rgba(34, 197, 94, 0.15);
        color: #4ade80;
        margin-left: 8px;
        letter-spacing: 0.5px;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def read_logs() -> list[dict]:
    """
    Read and parse the shared JSON log file produced by the SOAR engine.

    The engine (app.py) appends threat events here in real time.
    Returns an empty list if the file doesn't exist or is malformed —
    so the dashboard stays stable even before any threats are detected.
    """
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
            return json.loads(content) if content else []
    except (json.JSONDecodeError, IOError):
        # JSONDecodeError: file is mid-write (race condition) — skip this cycle
        # IOError: permission / disk error — fail silently
        return []


def get_severity(entropy: float) -> tuple[str, str]:
    """
    Map a normalised entropy score (0–10) to a CSS class and label.

    Entropy measures payload randomness:
      >= 8.0  → CRITICAL (highly randomised, likely encrypted attack traffic)
      >= 5.0  → HIGH     (moderately random, suspicious)
      <  5.0  → MEDIUM   (low entropy, possibly scripted/structured attack)

    Returns:
        (css_class, severity_label) — used to style the threat card.
    """
    if entropy >= 8.0:
        return "severity-critical", "CRITICAL"
    elif entropy >= 5.0:
        return "severity-high", "HIGH"
    return "severity-medium", "MEDIUM"


def get_attack_badge(attack_type: str) -> str:
    """
    Return an HTML pill badge for a given attack type string.

    The badge provides a quick visual cue about the threat category:
      VOLUMETRIC_FLOOD → red   ⚡ FLOOD
      STEALTH_RECON    → purple 🔍 RECON
      UDP_FLOOD        → orange 🌊 UDP

    Unknown attack types fall back to the red flood style.
    """
    badge_map = {
        "VOLUMETRIC_FLOOD": ("badge-flood", "⚡ FLOOD"),
        "STEALTH_RECON":    ("badge-recon", "🔍 RECON"),
        "UDP_FLOOD":        ("badge-udp",   "🌊 UDP"),
    }
    cls, label = badge_map.get(attack_type, ("badge-flood", attack_type))
    return f'<span class="badge {cls}">{label}</span>'


# ---------------------------------------------------------------------------
# HEADER BAR
# Two columns: title (left) + live status indicator (right)
# ---------------------------------------------------------------------------
col_title, col_status = st.columns([3, 1])

with col_title:
    st.markdown("# 🛡️ Astra-SOAR Dashboard")
    st.caption("Production-Grade Autonomous Network Defense — Live NIC Telemetry")

with col_status:
    # Animated green dot + bold text shown top-right
    st.markdown(
        '<div style="text-align:right; padding-top:20px;">'
        '<span class="status-dot status-active"></span>'
        '<b style="color:#22c55e;">GUARD MODE ACTIVE</b>'
        '</div>',
        unsafe_allow_html=True,
    )

st.markdown("---")


# ---------------------------------------------------------------------------
# SIDEBAR — TESTING WORKBENCH
# Allows the operator to inject controlled synthetic attacks against a
# target IP to verify the SOAR engine detects and logs them correctly.
#
# Two simulations available:
#   1. UDP Flood  — sends rapid large UDP packets to trigger VOLUMETRIC_FLOOD
#   2. Port Scan  — connects to 50 sequential ports to trigger STEALTH_RECON
#
# Both run in daemon threads so they don't block the Streamlit main thread.
# Using 127.0.0.1 (loopback) is safest — traffic stays on the local machine.
# ---------------------------------------------------------------------------
st.sidebar.markdown("## 🎛️ Testing Workbench")
st.sidebar.markdown("Generate controlled network traffic to test detection.")

# Operator-configurable parameters
target_ip   = st.sidebar.text_input("Target IP", value="127.0.0.1",
                                    help="Loopback is safest for testing")
packet_size = st.sidebar.slider("Payload Size (bytes)", 64, 1450, 1200)
burst_secs  = st.sidebar.slider("Burst Duration (seconds)", 1, 10, 3)


if st.sidebar.button("🔥 Inject UDP Flood Simulation", use_container_width=True):
    def _flood_sim():
        """
        Send a burst of large UDP packets to the target IP.
        The SOAR engine should detect this as VOLUMETRIC_FLOOD or UDP_FLOOD
        once the packet rate exceeds FLOOD_PPS_THRESHOLD (default: 40 pps).
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            end_time = time.time() + burst_secs
            while time.time() < end_time:
                # Send payload of repeated 'X' bytes — low entropy, high volume
                sock.sendto(b"X" * packet_size, (target_ip, 9999))
            sock.close()
        except OSError:
            pass  # Target unreachable or socket error — simulation still useful

    threading.Thread(target=_flood_sim, daemon=True).start()
    st.sidebar.success(f"🚀 Simulation deployed → {target_ip} for {burst_secs}s")


if st.sidebar.button("🥷 Inject Port Scan Simulation", use_container_width=True):
    def _scan_sim():
        """
        Attempt TCP connections to 50 sequential ports (8000–8049).
        The SOAR engine detects this as STEALTH_RECON once the unique
        destination port count exceeds RECON_PORT_THRESHOLD (default: 15).
        Each connection attempt has a 20ms timeout to keep the scan fast.
        """
        for port in range(8000, 8050):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.02)       # 20ms timeout per port — fast sweep
                s.connect((target_ip, port))
                s.close()
            except OSError:
                pass  # Connection refused / timeout is expected — just move on

    threading.Thread(target=_scan_sim, daemon=True).start()
    st.sidebar.success(f"🔍 Recon sweep deployed → {target_ip}:8000-8049")


st.sidebar.markdown("---")
st.sidebar.markdown("##### System Info")
# Show the operator exactly which files are being used — useful for debugging
st.sidebar.code(f"Log file : {LOG_FILE}\nReports  : {REPORT_DIR}", language="text")


# ---------------------------------------------------------------------------
# MAIN DASHBOARD — read the latest threat log on every refresh cycle
# ---------------------------------------------------------------------------
logs = read_logs()


# ---------------------------------------------------------------------------
# KPI METRICS ROW
# Four tiles showing summary counts from the current log window.
# The log is capped at MAX_LOG_ENTRIES (50) by the engine, so these numbers
# reflect recent activity rather than an all-time total.
# ---------------------------------------------------------------------------
m1, m2, m3, m4 = st.columns(4)

with m1:
    # Total number of threat events in the current log window
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value">{len(logs)}</div>
        <div class="metric-label">Total Threats</div>
    </div>
    """, unsafe_allow_html=True)

with m2:
    # Count of TCP/UDP volumetric flood events
    flood_count = sum(1 for l in logs if l.get("attack_type") == "VOLUMETRIC_FLOOD")
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value">{flood_count}</div>
        <div class="metric-label">Flood Events</div>
    </div>
    """, unsafe_allow_html=True)

with m3:
    # Count of port sweep / reconnaissance events
    recon_count = sum(1 for l in logs if l.get("attack_type") == "STEALTH_RECON")
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value">{recon_count}</div>
        <div class="metric-label">Recon Events</div>
    </div>
    """, unsafe_allow_html=True)

with m4:
    # Highest entropy value seen — indicates most randomised (dangerous) payload
    peak_entropy = max((l.get("entropy", 0) for l in logs), default=0)
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value">{peak_entropy}</div>
        <div class="metric-label">Peak Entropy</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# LIVE INTRUSION LOG STREAM
# Renders each threat event as a styled card with:
#   - Timestamp, attack type badge, severity label
#   - Source IP → Destination IP, payload size
#   - AI-generated analyst brief (from Gemini or rule-based fallback)
#   - Staged firewall remediation command
#   - 3-step agent execution pipeline timeline
#   - Download button for the PDF forensic report
# ---------------------------------------------------------------------------
st.markdown("### 🖥️ Live Intrusion Log Stream")

if not logs:
    # Shown when the engine is running but no threats have been detected yet
    st.info("🟢 **System Nominal** — No anomalies detected. Awaiting network activity.")
else:
    # Deduplicate entries with the same (timestamp, src_ip, attack_type) key.
    # This prevents duplicate cards if the JSON file is read mid-write.
    # reversed(logs) puts newest events at the top of the dashboard.
    unique_logs = []
    seen = set()
    for entry in reversed(logs):
        key = (entry.get("timestamp"), entry.get("src_ip"), entry.get("attack_type"))
        if key not in seen:
            unique_logs.append(entry)
            seen.add(key)

    for idx, entry in enumerate(unique_logs):

        # ── Extract display values ──────────────────────────────────────────
        entropy        = entry.get("entropy", 0)
        severity_class, severity_label = get_severity(entropy)
        attack_type    = entry.get("attack_type", "UNKNOWN")
        badge_html     = get_attack_badge(attack_type)
        # Red for CRITICAL, orange for everything else
        sev_color      = '#ef4444' if severity_label == 'CRITICAL' else '#f97316'

        # ── Main threat card HTML ───────────────────────────────────────────
        # Built as an f-string rather than Streamlit columns so we can apply
        # our custom CSS classes (log-card, severity-*, etc.) directly.
        card_html = (
            f'<div class="log-card {severity_class}">'

            # — Row 1: timestamp | badge | severity | entropy score —
            f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">'
            f'<div>'
            f'<code style="color:#38bdf8;">[{entry["timestamp"]}]</code>'
            f'&nbsp;{badge_html}&nbsp;'
            f'<span style="color:{sev_color};font-weight:700;">[{severity_label}]</span>'
            f'</div>'
            f'<div style="color:#64748b;font-size:0.75rem;">Entropy {entropy}/10</div>'
            f'</div>'

            # — Row 2: source IP → destination IP, payload bytes —
            f'<div style="margin-bottom:8px;">'
            f'<span style="color:#94a3b8;">Source:</span> '
            f'<b style="color:#f8fafc;">{entry.get("src_ip", "?")}</b>'
            f'<span style="color:#475569;"> &rarr; </span>'
            f'<b style="color:#f8fafc;">{entry.get("dst_ip", "?")}</b>'
            f'<span style="color:#64748b;margin-left:12px;">{entry.get("bytes", 0)} bytes</span>'
            f'</div>'

            # — Row 3: AI analyst brief (Gemini or rule-based fallback) —
            f'<div style="margin-bottom:8px;">'
            f'<span style="color:#94a3b8;">&#129504; AI Brief:</span> '
            f'<i style="color:#cbd5e1;">"{entry.get("ai_summary", "Pending...")}"</i>'
            f'</div>'

            # — Row 4: staged iptables firewall command —
            f'<div style="color:#475569;font-size:0.78rem;">'
            f'<span style="color:#94a3b8;">&#9876;&#65039; Remediation:</span> '
            f'<code style="font-size:0.75rem;">{entry.get("command", "")}</code>'
            f'</div>'

            f'</div>'  # close .log-card
        )
        st.markdown(card_html, unsafe_allow_html=True)

        # ── Agent Execution Pipeline Timeline ──────────────────────────────
        # Each threat event records the 3 agents that processed it:
        #   Step 1 — INGRESS SENSOR  (Data Plane)     → detected the anomaly
        #   Step 2 — INTELLIGENCE    (Reasoning Plane) → computed entropy + AI brief
        #   Step 3 — REMEDIATOR      (Action Plane)    → compiled firewall rule + PDF
        #
        # Rendered separately from the card to avoid HTML indentation issues
        # with nested f-strings inside the main card_html block.
        pipeline = entry.get("agent_pipeline", [])
        if pipeline:
            # Maps the icon field stored in the log to CSS class + step number
            step_styles = {
                "radar":  ("step-sensor", "1"),  # Ingress Sensor — blue
                "brain":  ("step-intel",  "2"),  # Intelligence   — purple
                "shield": ("step-shield", "3"),  # Remediator     — green
            }

            steps_html = ""
            for step in pipeline:
                dot_cls, dot_num = step_styles.get(step.get("icon", ""), ("step-sensor", "?"))
                steps_html += (
                    f'<div class="pipeline-step">'
                    f'<div class="step-dot {dot_cls}">{dot_num}</div>'
                    f'<div style="flex:1;">'

                    # Agent name + role label + DONE badge + timestamp (right-aligned)
                    f'<div class="step-header">'
                    f'<div>'
                    f'<span class="step-agent">{step.get("agent", "")}</span>'
                    f'<span class="step-role">({step.get("role", "")})</span>'
                    f'<span class="step-status">DONE</span>'
                    f'</div>'
                    f'<span class="step-time">{step.get("time", "")}</span>'
                    f'</div>'

                    # What the agent did (short summary)
                    f'<div class="step-action">{step.get("action", "")}</div>'
                    # Detailed description (timestamps, thresholds, file names)
                    f'<div class="step-detail">{step.get("detail", "")}</div>'

                    f'</div>'
                    f'</div>'
                )

            pipe_html = (
                f'<div class="pipeline-container">'
                f'<div class="pipeline-title">Agent Execution Pipeline</div>'
                f'{steps_html}'
                f'</div>'
            )
            st.markdown(pipe_html, unsafe_allow_html=True)

        # ── PDF Forensic Report Download Button ────────────────────────────
        # app.py generates a PDF report for every threat and stores the
        # filename in the log entry. If the file exists on disk, show a
        # Streamlit download button so the operator can save it locally.
        #
        # Key uses the report filename (which includes microseconds) to
        # guarantee uniqueness across all entries — avoids Streamlit's
        # "DuplicateWidgetID" error on the 2-second rerun cycle.
        report_file = entry.get("report_file", "")
        report_path = os.path.join(REPORT_DIR, report_file)
        if report_file and os.path.exists(report_path):
            with open(report_path, "rb") as fp:
                st.download_button(
                    label=f"\U0001f4e5 Download Forensic Report (PDF) — {report_file}",
                    data=fp,
                    file_name=report_file,
                    mime="application/pdf",
                    key=f"dl_{report_file}",  # unique per report file
                )


# ---------------------------------------------------------------------------
# AUTO-REFRESH LOOP
# Streamlit reruns the entire script top-to-bottom on every interaction and
# on st.rerun(). Sleeping 2 seconds then calling st.rerun() creates a
# polling loop that refreshes the dashboard every ~2 seconds without needing
# WebSockets or a separate backend process.
#
# Trade-off: each rerun re-reads the log file and re-renders all cards.
# With MAX_LOG_ENTRIES=50 this is fast, but if you increase the log size
# significantly consider caching read_logs() with st.cache_data(ttl=2).
# ---------------------------------------------------------------------------
time.sleep(2)
st.rerun()