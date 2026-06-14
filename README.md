# 🛡️ Anti-Gravity SOAR: Autonomous Multi-Agent Network Defense

**A Production-Grade, Live-Network Security Operations Center (SOC) built for the Agents League Hackathon.**

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-UI-FF4B4B.svg)
![Scapy](https://img.shields.io/badge/Scapy-Network%20Sensing-green.svg)
![GenAI](https://img.shields.io/badge/Gemini-AI%20Analyst-orange.svg)

## 🎯 Project Overview
Most compliance agents parse static text documents. **Anti-Gravity SOAR** operates at the kernel layer. 

This project is a fully autonomous, live-network Intrusion Detection and Prevention System (IDPS). It binds directly to the physical Network Interface Card (NIC), sniffing raw socket telemetry in real-time to detect, classify, and neutralize cyberattacks before they exhaust system resources. 

By integrating **Shannon Entropy Analysis**, **Multi-Vector Threat Detection**, and a **Generative AI Analyst**, this platform bridges the gap between low-level packet analysis and high-level, human-readable security orchestration.

---

## 🧠 The Multi-Agent Architecture

The system utilizes a decoupled, three-stage agent pipeline:

## System Architecture
![Astra-SOAR Architecture](<img width="1536" height="1024" alt="ChatGPT Image Jun 14, 2026, 09_46_35 PM" src="https://github.com/user-attachments/assets/117e2aae-5ca6-4d1f-9a1d-d461adff4ed2" />
)

### 1. The Ingress Sensor Agent (Data Plane)
Built on `Scapy`, this agent continuously monitors raw IP/TCP/UDP frames on the active network interface. It uses dual-matrix tracking to identify anomalies without relying on static signature updates:
* **Velocity Matrix:** Detects Volumetric Floods (DoS/DDoS) by tracking packet arrival frequencies. If an IP exceeds 40 pps with payloads >500 bytes, it triggers the threshold.
* **Spatial Matrix:** Detects Stealth Reconnaissance (Port Scanning) by tracking destination port variations. If a single IP sweeps >15 unique local ports within a 1-second window, it flags the recon attempt.
* **UDP Flood Detection:** Monitors high-volume UDP traffic patterns targeting service disruption.

### 2. The Intelligence Agent (Reasoning Plane)
Once an anomaly is detected, the **Shannon Entropy** of the raw packet payload is mathematically calculated (0–8 bits, normalised to 0–10 scale). The agent then enriches the raw network data:
* **Generative AI SOC Analyst:** Streams the telemetry to a Large Language Model (Gemini 2.5 Flash) to dynamically generate a natural-language executive incident brief for human operators.
* **Rule-based Fallback:** If no API key is configured, the system generates structured severity-classified briefs autonomously.

### 3. The Remediator Agent (Action Plane)
Acting as the autonomous shield, this agent instantly compiles and logs dynamic Linux firewall commands (`iptables -A INPUT -s [IP] -j REJECT --reject-with tcp-reset`) to mathematically sever the attacker's connection and restore infrastructure integrity. Forensic incident reports are auto-exported per event.

---

## 🚀 How to Run Locally

### 1. Prerequisites
- **Python 3.11+**
- **Npcap** (Windows) or **libpcap** (Linux/macOS) — required by Scapy for raw packet capture
- **Administrator / root privileges** — required for NIC-level sniffing

### 2. Installation
```bash
git clone https://github.com/your-repo/zero_security_reasoning_agent.git
cd zero_security_reasoning_agent
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS
pip install -r requirements.txt
```

### 3. (Optional) Set Gemini API Key
```bash
set GEMINI_API_KEY=your_key_here          # Windows
# export GEMINI_API_KEY=your_key_here     # Linux/macOS
```

### 4. Start the SOAR Engine (Terminal 1)
```bash
python src/app.py
```

### 5. Start the Dashboard (Terminal 2)
```bash
python -m streamlit run src/gui.py
```

### 6. Trigger a Simulation (Terminal 3)
```bash
python src/simulate_scan.py              # Port scan simulation
python src/simulate_scan.py 10.0.0.1     # Custom target IP
```

---

## 📁 Project Structure
```
zero_security_reasoning_agent/
├── src/
│   ├── app.py               # Core SOAR engine (packet capture + detection)
│   ├── gui.py                # Streamlit live dashboard
│   └── simulate_scan.py      # Safe port-scan simulator
├── data/
│   ├── live_soar_logs.json   # Shared rolling threat log (engine ↔ dashboard)
│   ├── reports/              # Auto-generated forensic incident reports
│   ├── synthetic_analysts.json
│   └── synthetic_playbooks.json
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🔐 Safety & Ethics
This tool is designed for **defensive security research** on networks you own or have explicit authorisation to test. The port scan simulator targets only the local machine by default. Never use this tool against networks without permission.
